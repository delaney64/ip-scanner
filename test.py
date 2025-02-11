"""
IP Scanner with Threat Intelligence Integration
"""

import ipaddress
import logging
from typing import Dict
import json
from datetime import datetime
import os
from pathlib import Path
from getpass import getpass
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class APIKeyHandler:
    """Handles secure storage and retrieval of API keys."""

    def __init__(self):
        self.config_dir = Path.home() / '.ip_scanner'
        self.config_path = self.config_dir / 'config.enc'
        self.salt_path = self.config_dir / 'salt'

    def _get_encryption_key(self, password: str, salt: bytes) -> bytes:
        """Generate encryption key from password and salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def setup_api_keys(self):
        """Interactive setup for API keys with encryption."""
        # Create config directory
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # Generate salt
        salt = os.urandom(16)
        with open(self.salt_path, 'wb') as f:
            f.write(salt)

        print("\nPlease enter your API keys:")
        keys = {
            'virustotal': getpass("VirusTotal API Key: "),
            'graynoise': getpass("GrayNoise API Key: "),
            'shodan': getpass("Shodan API Key: ")
        }

        master_password = getpass("Create a master password to encrypt your API keys: ")
        confirm_password = getpass("Confirm master password: ")

        if master_password != confirm_password:
            raise ValueError("Passwords do not match!")

        # Encrypt and save
        key = self._get_encryption_key(master_password, salt)
        f = Fernet(key)
        encrypted_data = f.encrypt(json.dumps(keys).encode())

        with open(self.config_path, 'wb') as f:
            f.write(encrypted_data)

        print("\nAPI keys have been securely stored!")

    def get_api_keys(self) -> Dict[str, str]:
        """Retrieve and decrypt API keys."""
        if not self.config_path.exists() or not self.salt_path.exists():
            raise FileNotFoundError("API keys not configured. Please configure them first.")

        with open(self.salt_path, 'rb') as f:
            salt = f.read()

        master_password = getpass("Enter master password to decrypt API keys: ")

        try:
            key = self._get_encryption_key(master_password, salt)
            f = Fernet(key)

            with open(self.config_path, 'rb') as file:
                encrypted_data = file.read()

            decrypted_data = f.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except Exception as e:
            raise ValueError("Failed to decrypt API keys. Wrong password?")

class IPScanner:
    def __init__(self, api_keys: Dict[str, str] = None):
        self.api_keys = api_keys or {}
        print("Scanner initialized" + (" with API keys" if api_keys else ""))

    def validate_ip(self, ip_address: str) -> bool:
        """Validate IPv4 or IPv6 address."""
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False

    async def query_virustotal(self, ip_address: str) -> Dict:
        """Query VirusTotal API for IP information."""
        if not self.api_keys.get('virustotal'):
            return {'error': 'VirusTotal API key not configured'}

        url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
        params = {
            'apikey': self.api_keys['virustotal'],
            'ip': ip_address
        }

        try:
            response = requests.get(url, params=params)
            response.raise_for_status()
            data = response.json()

            return {
                'detected_urls': len(data.get('detected_urls', [])),
                'malicious_detections': len([v for v in data.get('detected_urls', []) if v['positives'] > 0]),
                'last_resolved_domains': [d.get('hostname', '') for d in data.get('resolutions', [])[:5]],
                'detected_files': len(data.get('detected_downloaded_samples', [])),
                'malicious_files': len([f for f in data.get('detected_downloaded_samples', []) if f['positives'] > 0])
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal API error: {e}")
            return {'error': f"VirusTotal API error: {str(e)}"}

    async def scan_ip(self, ip_address: str) -> Dict:
        """Scan an IP address and gather threat intelligence."""
        if not self.validate_ip(ip_address):
            raise ValueError(f"Invalid IP address: {ip_address}")

        results = {
            'ip': ip_address,
            'timestamp': datetime.now().isoformat(),
            'status': 'valid',
            'api_keys_configured': bool(self.api_keys)
        }

        # Add VirusTotal results if API key is configured
        if self.api_keys.get('virustotal'):
            print("Querying VirusTotal...")
            vt_results = await self.query_virustotal(ip_address)
            results['virustotal'] = vt_results

        return results

async def main():
    print("\n=== IP Scanner with Threat Intelligence ===\n")
    key_handler = APIKeyHandler()
    scanner = None

    while True:
        print("\nOptions:")
        print("1. Configure API Keys")
        print("2. Scan IP Address")
        print("3. Exit")

        choice = input("\nSelect an option (1-3): ")

        if choice == "1":
            try:
                key_handler.setup_api_keys()
                # Reinitialize scanner with new keys
                api_keys = key_handler.get_api_keys()
                scanner = IPScanner(api_keys)
            except Exception as e:
                print(f"\nError configuring API keys: {str(e)}")

        elif choice == "2":
            try:
                if not scanner:
                    try:
                        api_keys = key_handler.get_api_keys()
                        scanner = IPScanner(api_keys)
                    except FileNotFoundError:
                        print("\nAPI keys not configured. Using scanner without API access.")
                        scanner = IPScanner()
                    except ValueError as e:
                        print(f"\nError accessing API keys: {str(e)}")
                        print("Using scanner without API access.")
                        scanner = IPScanner()

                ip_to_scan = input("\nEnter IP address to scan (e.g., 8.8.8.8): ")
                results = await scanner.scan_ip(ip_to_scan)

                print("\n=== Scan Results ===")
                print(f"IP Address: {results['ip']}")
                print(f"Scan Time: {results['timestamp']}")
                print(f"Status: {results['status']}")
                print(f"API Keys Configured: {'Yes' if results['api_keys_configured'] else 'No'}")

                # Display VirusTotal results if available
                if 'virustotal' in results:
                    vt_data = results['virustotal']
                    print("\n=== VirusTotal Results ===")
                    if 'error' in vt_data:
                        print(f"Error: {vt_data['error']}")
                    else:
                        print(f"Detected URLs: {vt_data['detected_urls']}")
                        print(f"Malicious Detections: {vt_data['malicious_detections']}")
                        print(f"Detected Files: {vt_data['detected_files']}")
                        print(f"Malicious Files: {vt_data['malicious_files']}")
                        if vt_data['last_resolved_domains']:
                            print("\nLast Resolved Domains:")
                            for domain in vt_data['last_resolved_domains']:
                                print(f"  - {domain}")

                filename = f"scan_results_{ip_to_scan.replace('.', '_')}.json"
                with open(filename, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"\nResults saved to {filename}")

            except Exception as e:
                print(f"\nError during scan: {str(e)}")

            input("\nPress Enter to continue...")

        elif choice == "3":
            print("\nExiting IP Scanner. Goodbye!")
            break

        else:
            print("\nInvalid choice. Please select 1-3.")

if __name__ == "__main__":
    print("Starting IP Scanner...")
    try:
        import asyncio
        print("Running main program...")
        asyncio.run(main())
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        import traceback
        print(traceback.format_exc())
        input("Press Enter to exit...")