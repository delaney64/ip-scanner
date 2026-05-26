"""
IP Scanner with Threat Intelligence Integration

Gathers threat intelligence on IP addresses by querying VirusTotal, GrayNoise,
and Shodan. Maps findings to MITRE ATT&CK techniques organized by STRIDE category.
API keys are stored locally using PBKDF2-derived Fernet encryption.

Author: Delaney Scarangella
"""

import argparse
import asyncio
import base64
import configparser
import ipaddress
import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from getpass import getpass
from pathlib import Path
from typing import Dict

import requests
import shodan
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# STRIDE threat model categories
# ---------------------------------------------------------------------------

class StrideCategory(Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


# ---------------------------------------------------------------------------
# Encrypted API key storage
# ---------------------------------------------------------------------------

class APIKeyHandler:
    """Stores and retrieves API keys using PBKDF2 + Fernet encryption."""

    def __init__(self):
        self.config_path = Path.home() / '.ip_scanner' / 'config.enc'
        self.salt_path = Path.home() / '.ip_scanner' / 'salt'
        self.config_dir = self.config_path.parent

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def setup_api_keys(self):
        """Interactive setup — prompts for keys and master password, then encrypts and saves."""
        self.config_dir.mkdir(parents=True, exist_ok=True)

        salt = os.urandom(16)
        with open(self.salt_path, 'wb') as f:
            f.write(salt)

        print("Please enter your API keys:")
        vt_key = getpass("VirusTotal API Key: ")
        gn_key = getpass("GrayNoise API Key: ")
        shodan_key = getpass("Shodan API Key: ")
        master_password = getpass("Create a master password: ")

        key = self._derive_key(master_password, salt)
        fernet = Fernet(key)

        payload = json.dumps({
            'virustotal': vt_key,
            'graynoise': gn_key,
            'shodan': shodan_key
        })

        with open(self.config_path, 'wb') as f:
            f.write(fernet.encrypt(payload.encode()))

        logger.info("API keys stored successfully.")

    def get_api_keys(self) -> Dict[str, str]:
        """Decrypts and returns stored API keys."""
        if not self.config_path.exists() or not self.salt_path.exists():
            raise FileNotFoundError("Keys not found. Run with --setup first.")

        with open(self.salt_path, 'rb') as f:
            salt = f.read()

        master_password = getpass("Enter master password to decrypt API keys: ")
        key = self._derive_key(master_password, salt)
        fernet = Fernet(key)

        with open(self.config_path, 'rb') as f:
            encrypted_data = f.read()

        try:
            return json.loads(fernet.decrypt(encrypted_data).decode())
        except Exception as e:
            raise ValueError("Decryption failed — wrong password?") from e


# ---------------------------------------------------------------------------
# API config dataclass
# ---------------------------------------------------------------------------

@dataclass
class APIConfig:
    virustotal_api_key: str
    graynoise_api_key: str
    shodan_api_key: str


# ---------------------------------------------------------------------------
# Main scanner class
# ---------------------------------------------------------------------------

class IPScanner:
    """Queries VirusTotal, GrayNoise, Shodan, and MITRE ATT&CK for a given IP."""

    MITRE_CACHE_PATH = Path.home() / '.ip_scanner' / 'attack_cache.json'
    MITRE_CACHE_MAX_AGE_DAYS = 30
    MITRE_URL = (
        "https://raw.githubusercontent.com/mitre/cti/master/"
        "enterprise-attack/enterprise-attack.json"
    )

    # STRIDE → ATT&CK technique mapping
    STRIDE_MAPPING = {
        StrideCategory.SPOOFING:               ['T1071', 'T1534'],
        StrideCategory.TAMPERING:              ['T1565', 'T1565.001'],
        StrideCategory.REPUDIATION:            ['T1070', 'T1070.001'],
        StrideCategory.INFORMATION_DISCLOSURE: ['T1020', 'T1030'],
        StrideCategory.DENIAL_OF_SERVICE:      ['T1498', 'T1499'],
        StrideCategory.ELEVATION_OF_PRIVILEGE: ['T1068', 'T1548'],
    }

    def __init__(self, config: APIConfig):
        self.config = config
        self.shodan_api = shodan.Shodan(config.shodan_api_key)
        self.last_vt_request = 0
        self.vt_rate_limit = 4  # requests per minute (free tier)

    def validate_ip(self, ip_address: str) -> bool:
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False

    # --- Rate limiting ---

    def _rate_limit_vt(self):
        current_time = time.time()
        wait = (60 / self.vt_rate_limit) - (current_time - self.last_vt_request)
        if wait > 0:
            logger.debug(f"Rate limiting: waiting {wait:.2f}s")
            time.sleep(wait)
        self.last_vt_request = time.time()

    # --- API queries ---

    async def query_virustotal(self, ip_address: str) -> Dict:
        self._rate_limit_vt()
        url = "https://www.virustotal.com/vtapi/v2/ip-address/report"
        params = {'apikey': self.config.virustotal_api_key, 'ip': ip_address}
        try:
            response = requests.get(url, params=params, timeout=15)
            response.raise_for_status()
            data = response.json()
            return {
                'malicious_detections': len([
                    v for v in data.get('detected_urls', []) if v['positives'] > 0
                ]),
                'associated_domains': data.get('resolutions', [])[:5],
                'related_files': data.get('detected_downloaded_samples', [])[:5],
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal API error: {e}")
            return {}

    async def query_graynoise(self, ip_address: str) -> Dict:
        url = f"https://api.greynoise.io/v2/noise/context/{ip_address}"
        headers = {'key': self.config.graynoise_api_key}
        try:
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            data = response.json()
            return {
                'classification': data.get('classification', 'Unknown'),
                'tags': data.get('tags', []),
                'last_seen': data.get('last_seen', 'Never'),
                'metadata': {
                    'organization': data.get('metadata', {}).get('organization', 'Unknown'),
                    'country': data.get('metadata', {}).get('country', 'Unknown'),
                },
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"GrayNoise API error: {e}")
            return {}

    async def query_shodan(self, ip_address: str) -> Dict:
        try:
            results = self.shodan_api.host(ip_address)
            return {
                'isp': results.get('isp', 'Unknown'),
                'open_ports': results.get('ports', []),
                'vulnerabilities': [
                    {
                        'cve': vuln,
                        'severity': results.get('vulns', {}).get(vuln, {}).get('severity', 'Unknown'),
                    }
                    for vuln in results.get('vulns', {})
                ],
                'location': {
                    'country': results.get('country_name', 'Unknown'),
                    'city': results.get('city', 'Unknown'),
                },
            }
        except shodan.APIError as e:
            logger.error(f"Shodan API error: {e}")
            return {}

    async def query_mitre_attack(self) -> Dict:
        """Returns STRIDE-mapped ATT&CK techniques, using a 30-day local cache."""
        attack_data = self._load_mitre_cache()
        technique_lookup = self._build_technique_lookup(attack_data)

        techniques = {}
        for category, technique_ids in self.STRIDE_MAPPING.items():
            techniques[category.value] = [
                {'id': tid, 'name': technique_lookup.get(tid, 'Unknown Technique')}
                for tid in technique_ids
            ]
        return techniques

    def _load_mitre_cache(self) -> Dict:
        if self.MITRE_CACHE_PATH.exists():
            age = datetime.now().timestamp() - self.MITRE_CACHE_PATH.stat().st_mtime
            if age < self.MITRE_CACHE_MAX_AGE_DAYS * 86400:
                logger.info("Loading MITRE ATT&CK data from local cache")
                with open(self.MITRE_CACHE_PATH, 'r') as f:
                    return json.load(f)
            logger.info("Cache expired — refreshing MITRE ATT&CK data")
        else:
            logger.info("No cache found — fetching MITRE ATT&CK data")
        return self._fetch_and_cache_mitre()

    def _fetch_and_cache_mitre(self) -> Dict:
        try:
            logger.info("Fetching MITRE ATT&CK data from GitHub...")
            response = requests.get(self.MITRE_URL, timeout=30)
            response.raise_for_status()
            data = response.json()
            self.MITRE_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(self.MITRE_CACHE_PATH, 'w') as f:
                json.dump(data, f)
            logger.info(f"Cached to {self.MITRE_CACHE_PATH}")
            return data
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch MITRE ATT&CK data: {e}")
            return {'objects': []}

    def _build_technique_lookup(self, attack_data: Dict) -> Dict[str, str]:
        lookup = {}
        for obj in attack_data.get('objects', []):
            if obj.get('type') == 'attack-pattern':
                for ref in obj.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        lookup[ref['external_id']] = obj.get('name', 'Unknown')
        return lookup

    # --- Output formatting ---

    def format_output(self, ip_address: str, results: Dict) -> str:
        output = [f"\n{'='*50}", f"  Threat Intel Report: {ip_address}", f"{'='*50}\n"]

        # VirusTotal
        output.append("[ VirusTotal ]")
        vt = results.get('virustotal', {})
        output.append(f"  Malicious Detections : {vt.get('malicious_detections', 0)}")
        domains = ", ".join([d.get('hostname', '') for d in vt.get('associated_domains', [])])
        output.append(f"  Associated Domains   : {domains or 'None'}")
        files = ", ".join([f['sha256'][:16] + '...' for f in vt.get('related_files', [])[:3]])
        output.append(f"  Related Files        : {files or 'None'}\n")

        # GrayNoise
        output.append("[ GrayNoise ]")
        gn = results.get('graynoise', {})
        output.append(f"  Classification : {gn.get('classification', 'Unknown')}")
        output.append(f"  Tags           : {', '.join(gn.get('tags', [])) or 'None'}")
        output.append(f"  Last Seen      : {gn.get('last_seen', 'Never')}\n")

        # Shodan
        output.append("[ Shodan ]")
        sh = results.get('shodan', {})
        output.append(f"  ISP        : {sh.get('isp', 'Unknown')}")
        output.append(f"  Open Ports : {', '.join(map(str, sh.get('open_ports', []))) or 'None'}")
        vulns = sh.get('vulnerabilities', [])
        if vulns:
            output.append("  Vulnerabilities:")
            for v in vulns[:3]:
                output.append(f"    - {v['cve']} ({v['severity']})")
        output.append("")

        # MITRE ATT&CK
        output.append("[ MITRE ATT&CK — STRIDE Mapping ]")
        for category, techniques in results.get('mitre', {}).items():
            output.append(f"  {category}:")
            for t in techniques:
                output.append(f"    - {t['id']} : {t['name']}")

        output.append(f"\n{'='*50}\n")
        return "\n".join(output)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def run_scan(scanner: IPScanner, ip: str):
    results = {
        'virustotal': await scanner.query_virustotal(ip),
        'graynoise':  await scanner.query_graynoise(ip),
        'shodan':     await scanner.query_shodan(ip),
        'mitre':      await scanner.query_mitre_attack(),
    }
    print(scanner.format_output(ip, results))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IP Threat Intelligence Scanner")
    parser.add_argument("ip", nargs="?", help="IP address to scan")
    parser.add_argument("--setup", action="store_true", help="Run API key setup")
    args = parser.parse_args()

    handler = APIKeyHandler()

    if args.setup:
        handler.setup_api_keys()
    else:
        if not args.ip:
            parser.error("Please provide an IP address to scan.")

        keys = handler.get_api_keys()
        config = APIConfig(
            virustotal_api_key=keys['virustotal'],
            graynoise_api_key=keys['graynoise'],
            shodan_api_key=keys['shodan'],
        )
        scanner = IPScanner(config)

        if not scanner.validate_ip(args.ip):
            print(f"[!] Invalid IP address: {args.ip}")
            exit(1)

        print(f"[*] Scanning {args.ip}...")
        asyncio.run(run_scan(scanner, args.ip))