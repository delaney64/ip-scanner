"""
IP Scanner with Threat Intelligence Integration

This script provides comprehensive threat intelligence gathering capabilities for IP addresses
by integrating with multiple security services including VirusTotal, GrayNoise, Shodan, and
MITRE ATT&CK framework. It includes secure API key handling and detailed error reporting.

Author: Delaney
Date: February 2025
"""

import ipaddress
import json
import time
from typing import Dict, List, Optional, Union
import requests
from dataclasses import dataclass
from datetime import datetime
import logging
from enum import Enum
from taxii2client.v20 import Server
import shodan
import os
from pathlib import Path
import configparser
from getpass import getpass
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Set up logging with detailed formatting
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

class StrideCategory(Enum):
    """
    Enumeration of STRIDE threat model categories for classifying security threats.
    STRIDE is a model for identifying security threats developed by Microsoft.
    """
    SPOOFING = "Spoofing"  # Threats that impersonate something or someone else
    TAMPERING = "Tampering"  # Modification of data or code
    REPUDIATION = "Repudiation"  # Denial of having performed an action
    INFORMATION_DISCLOSURE = "Information Disclosure"  # Information leaks or exposure
    DENIAL_OF_SERVICE = "Denial of Service"  # Denial of service attacks
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"  # Gain unauthorized access

class APIKeyHandler:
    """
    Handles secure storage and retrieval of API keys using encryption.
    Keys are stored in an encrypted configuration file with a master password.
    """
    def __init__(self):
        self.config_path = Path.home() / '.ip_scanner' / 'config.enc'
        self.salt_path = Path.home() / '.ip_scanner' / 'salt'
        self.config_dir = self.config_path.parent
        
    def _get_encryption_key(self, password: str, salt: bytes) -> bytes:
        """
        Derives an encryption key from the master password using PBKDF2.
        
        Args:
            password: Master password for encrypting/decrypting API keys
            salt: Random salt for key derivation
            
        Returns:
            bytes: Derived encryption key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def setup_api_keys(self):
        """
        Interactive setup for API keys. Prompts user for keys and master password,
        then stores them securely in an encrypted configuration file.
        """
        # Create config directory if it doesn't exist
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate random salt for key derivation
        salt = os.urandom(16)
        with open(self.salt_path, 'wb') as f:
            f.write(salt)
            
        # Get API keys and master password from user
        print("Please enter your API keys:")
        vt_key = getpass("VirusTotal API Key: ")
        gn_key = getpass("GrayNoise API Key: ")
        shodan_key = getpass("Shodan API Key: ")
        
        master_password = getpass("Create a master password for encrypting API keys: ")
        
        # Create config parser and add API keys
        config = configparser.ConfigParser()
        config['API_KEYS'] = {
            'virustotal': vt_key,
            'graynoise': gn_key,
            'shodan': shodan_key
        }
        
        # Encrypt and save configuration
        key = self._get_encryption_key(master_password, salt)
        f = Fernet(key)
        
        # Convert config to string and encrypt
        config_str = json.dumps(dict(config['API_KEYS']))
        encrypted_data = f.encrypt(config_str.encode())
        
        # Save encrypted configuration
        with open(self.config_path, 'wb') as f:
            f.write(encrypted_data)
            
        logger.info("API keys have been securely stored")

    def get_api_keys(self) -> Dict[str, str]:
        """
        Retrieves API keys from the encrypted configuration file.
        
        Returns:
            Dict[str, str]: Dictionary containing API keys for each service
        
        Raises:
            FileNotFoundError: If configuration files don't exist
            ValueError: If decryption fails due to wrong password
        """
        if not self.config_path.exists() or not self.salt_path.exists():
            raise FileNotFoundError("API keys not configured. Please run setup_api_keys() first.")
            
        # Read salt and get master password
        with open(self.salt_path, 'rb') as f:
            salt = f.read()
            
        master_password = getpass("Enter master password to decrypt API keys: ")
        
        # Derive encryption key
        key = self._get_encryption_key(master_password, salt)
        f = Fernet(key)
        
        # Read and decrypt configuration
        with open(self.config_path, 'rb') as f:
            encrypted_data = f.read()
            
        try:
            decrypted_data = f.decrypt(encrypted_data)
            config = json.loads(decrypted_data.decode())
            return config
        except Exception as e:
            raise ValueError("Failed to decrypt API keys. Wrong password?") from e

@dataclass
class APIConfig:
    """Configuration class for storing API keys."""
    virustotal_api_key: str
    graynoise_api_key: str
    shodan_api_key: str
    
class IPScanner:
    """
    Main class for IP scanning and threat intelligence gathering.
    Integrates with multiple security services to provide comprehensive threat analysis.
    """
    
    def __init__(self, config: APIConfig):
        """
        Initialize the IP Scanner with API configurations.
        
        Args:
            config: APIConfig object containing API keys for various services
        """
        self.config = config
        self.shodan_api = shodan.Shodan(config.shodan_api_key)
        # Initialize rate limiting parameters
        self.last_vt_request = 0
        self.vt_rate_limit = 4  # requests per minute
        
    def validate_ip(self, ip_address: str) -> bool:
        """
        Validate whether a string is a properly formatted IPv4 or IPv6 address.
        
        Args:
            ip_address: String containing the IP address to validate
            
        Returns:
            bool: True if valid IP address, False otherwise
        """
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False
            
    async def _rate_limit_check(self):
        """
        Internal method to handle API rate limiting.
        Ensures we don't exceed API provider's rate limits.
        """
        current_time = time.time()
        if current_time - self.last_vt_request < (60 / self.vt_rate_limit):
            wait_time = (60 / self.vt_rate_limit) - (current_time - self.last_vt_request)
            logger.debug(f"Rate limiting: waiting {wait_time:.2f} seconds")
            time.sleep(wait_time)
        self.last_vt_request = current_time
            
    async def query_virustotal(self, ip_address: str) -> Dict:
        """
        Query VirusTotal API for IP reputation and associated threats.
        
        Args:
            ip_address: IP address to query
            
        Returns:
            Dict containing:
                - malicious_detections: Number of vendors flagging as malicious
                - associated_domains: List of domains associated with the IP
                - related_files: List of malicious files downloaded from this IP
        """
        await self._rate_limit_check()
        url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
        params = {
            'apikey': self.config.virustotal_api_key,
            'ip': ip_address
        }
        
        try:
            response = requests.get(url, params=params)
            response.raise_for_status()
            data = response.json()
            
            return {
                'malicious_detections': len([v for v in data.get('detected_urls', []) if v['positives'] > 0]),
                'associated_domains': data.get('resolutions', [])[:5],
                'related_files': data.get('detected_downloaded_samples', [])[:5]
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal API error: {e}")
            return {}
            
    async def query_graynoise(self, ip_address: str) -> Dict:
        """
        Query GrayNoise API for IP noise and classification data.
        GrayNoise helps identify Internet background noise and common scanners.
        
        Args:
            ip_address: IP address to query
            
        Returns:
            Dict containing:
                - classification: IP classification (malicious/benign/unknown)
                - tags: List of activity tags associated with the IP
                - last_seen: Timestamp of last activity
                - metadata: Additional context about the IP
        """
        url = f"https://api.greynoise.io/v2/noise/context/{ip_address}"
        headers = {'key': self.config.graynoise_api_key}
        
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            
            return {
                'classification': data.get('classification', 'Unknown'),
                'tags': data.get('tags', []),
                'last_seen': data.get('last_seen', 'Never'),
                'metadata': {
                    'organization': data.get('metadata', {}).get('organization', 'Unknown'),
                    'country': data.get('metadata', {}).get('country', 'Unknown')
                }
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"GrayNoise API error: {e}")
            return {}
            
    async def query_shodan(self, ip_address: str) -> Dict:
        """
        Query Shodan API for open ports, services, and vulnerabilities.
        Shodan provides internet-wide scanning data and service identification.
        
        Args:
            ip_address: IP address to query
            
        Returns:
            Dict containing:
                - isp: Internet Service Provider information
                - open_ports: List of open ports
                - vulnerabilities: List of CVEs and their severity
                - location: Geographical location data
        """
        try:
            results = self.shodan_api.host(ip_address)
            
            return {
                'isp': results.get('isp', 'Unknown'),
                'open_ports': results.get('ports', []),
                'vulnerabilities': [
                    {
                        'cve': vuln,
                        'severity': results.get('vulns', {}).get(vuln, {}).get('severity', 'Unknown')
                    }
                    for vuln in results.get('vulns', {})
                ],
                'location': {
                    'country': results.get('country_name', 'Unknown'),
                    'city': results.get('city', 'Unknown')
                }
            }
        except shodan.APIError as e:
            logger.error(f"Shodan API error: {e}")
            return {}
            
    async def query_mitre_attack(self) -> Dict:
        """
        Query MITRE ATT&CK framework and map techniques to STRIDE categories.
        Provides tactical and technical threat intelligence context.
        
        Returns:
            Dict mapping STRIDE categories to relevant MITRE ATT&CK techniques
        """
        server = Server("https://cti-taxii.mitre.org/taxii/")
        api_root = server.api_roots[0]
        
        # Map MITRE techniques to STRIDE categories
        # This mapping is based on common attack patterns and their primary impact
        stride_mapping = {
            StrideCategory.SPOOFING: ['T1071', 'T1534'],  # Application Layer Protocol, Internal Spearphishing
            StrideCategory.TAMPERING: ['T1565', 'T1565.001'],  # Data Manipulation
            StrideCategory.REPUDIATION: ['T1070', 'T1070.001'],  # Indicator Removal
            StrideCategory.INFORMATION_DISCLOSURE: ['T1020', 'T1030'],  # Automated Exfiltration
            StrideCategory.DENIAL_OF_SERVICE: ['T1498', 'T1499'],  # Network Denial of Service
            StrideCategory.ELEVATION_OF_PRIVILEGE: ['T1068', 'T1548']  # Exploitation for Privilege Escalation
        }
        
        techniques = {}
        for category, technique_ids in stride_mapping.items():
            techniques[category.value] = []
            for technique_id in technique_ids:
                # In a real implementation, you would query the TAXII server
                # This is a simplified version
                techniques[category.value].append({
                    'id': technique_id,
                    'name': f"Technique {technique_id}"
                })
                
        return techniques
        
    def format_output(self, ip_address: str, results: Dict) -> str:
        """
        Format the scanning results into a human-readable string.
        
        Args:
            ip_address: The scanned IP address
            results: Dictionary containing results from all API queries
            
        Returns:
            str: Formatted string containing all scanning results
        """
        output = [f"IP Address: {ip_address}\n"]
        
        # VirusTotal Section
        output.append("### VirusTotal:")
        vt_data = results.get('virustotal', {})
        output.append(f"- Malicious Detections: {vt_data.get('malicious_detections', 0)}")
        output.append("- Associated Domains: " + ", ".join([d.get('hostname', '') for d in vt_data.get('associated_domains', [])]))
        output.append("- Related Files: " + ", ".join([f['sha256'] for f in vt_data.get('related_files', [])[:3]]))
        
        # GrayNoise Section
        output.append("\n### GrayNoise:")
        gn_data = results.get('graynoise', {})
        output.append(f"- Classification: {gn_data.get('classification', 'Unknown')}")
        output.append(f"- Tags: {', '.join(gn_data.get('tags', []))}")
        output.append(f"- Last Seen: {gn_data.get('last_seen', 'Never')}")
        
        # Shodan Section
        output.append("\n###