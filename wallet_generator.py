import secrets
import hashlib
import base58
import ecdsa
import requests
import time
import json
import sys
import gc
from typing import Dict, List, Optional


class BitcoinWalletGenerator:
    def __init__(self):
        self.address_types = {
            "1": "P2PKH (starts with 1) - Legacy",
            "3": "P2SH-P2WPKH (starts with 3) - SegWit Compatible",
            "bc": "Bech32 (starts with bc1) - Native SegWit"
        }
        self.BECH32_ALPHABET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
        self.current_wallet = None
        self.author = "Slavik Khachatryan"
        self.donate_address = "bc1q6t8377r83328j8ret6t2fpp9z92224d8k3a53c"
        self.private_key_displayed = False

    def print_banner(self):
        """Print beautiful banner"""
        banner = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║        _______   ______  ________  ______    ______   ______  __    __        ║
║       /       \ /      |/        |/      \  /      \ /      |/  \  /  |       ║
║       $$$$$$$  |$$$$$$/ $$$$$$$$//$$$$$$  |/$$$$$$  |$$$$$$/ $$  \ $$ |       ║
║       $$ |__$$ |  $$ |     $$ |  $$ |  $$/ $$ |  $$ |  $$ |  $$$  \$$ |       ║
║       $$    $$<   $$ |     $$ |  $$ |      $$ |  $$ |  $$ |  $$$$  $$ |       ║
║       $$$$$$$  |  $$ |     $$ |  $$ |   __ $$ |  $$ |  $$ |  $$ $$ $$ |       ║
║       $$ |__$$ | _$$ |_    $$ |  $$ \__/  |$$ \__$$ | _$$ |_ $$ |$$$$ |       ║
║       $$    $$/ / $$   |   $$ |  $$    $$/ $$    $$/ / $$   |$$ | $$$ |       ║ 
║       $$$$$$$/  $$$$$$/    $$/    $$$$$$/   $$$$$$/  $$$$$$/ $$/   $$/        ║
║                                                                               ║                                                                                                         
║                  Secure BTC Wallet Generator  |  v1.0                         ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
        """
        print("\033[92m" + banner + "\033[0m")
        print(f"\033[92m{' ' * 25}Created by: {self.author}\033[0m")
        print(f"\033[93m{' ' * 20}Donate BTC: {self.donate_address}\033[0m")
        print(f"\033[92m{' ' * 25}🔒 Enhanced Security Mode\033[0m")
        print("\033[92m" + "═" * 81 + "\033[0m\n")

    def print_security_warnings(self):
        """Print security warnings"""
        warnings = """
╔═════════════════════════════════════════════════════════════════════════════╗
║                         🔒  SECURITY WARNINGS                               ║  
╠═════════════════════════════════════════════════════════════════════════════╣
║                                                                             ║
║    ⚠️   NEVER use this wallet for large amounts                             ║
║    ⚠️   Generate wallets on OFFLINE computer only                           ║
║    ⚠️   Private keys are stored in RAM - clear after use                    ║
║    ⚠️   Make secure backups (paper, hardware)                               ║
║    ⚠️   Assume this computer may be compromised                             ║
║                                                                             ║  
║    ✅  For large amounts use:                                               ║ 
║       • Hardware wallets (Ledger, Trezor)                                   ║ 
║       • Multisig wallets                                                    ║
║       • Professional custody solutions                                      ║
║                                                                             ║ 
╚═════════════════════════════════════════════════════════════════════════════╝
        """
        print("\033[91m" + warnings + "\033[0m")

    def show_main_menu(self):
        """Show main menu after wallet generation"""
        menu = """
╔══════════════════════════════════════════════════════════════════════════════════════
║                            🚀 MAIN MENU                                             
╠══════════════════════════════════════════════════════════════════════════════════════
║                                                                                      
║    \033[96m1\033[0m. 🔍 Check Balance & Transactions (Internet required)                     
║    \033[96m2\033[0m. 🔑 Show Private Keys (Secure display)                           
║    \033[96m3\033[0m. 🎲 Generate New Wallet                                          
║    \033[96m4\033[0m. 🚪 Exit & Clear Memory                                          
║                                                                                      
║    \033[90mNote: Private keys are NEVER stored on disk and are cleared from memory   
║         when you exit the program or generate a new wallet.                          
║                                                                                      
╚══════════════════════════════════════════════════════════════════════════════════════
        """
        print("\033[95m" + menu + "\033[0m")

    def show_address_types(self):
        """Show available address types"""
        print("\033[93m🎯 Choose Bitcoin address type:\033[0m")
        for key, description in self.address_types.items():
            print(f"\033[96m  [{key}]\033[0m - {description}")

    def secure_memory_cleanup(self):
        """Overwrite sensitive data in memory and force cleanup"""
        try:
            if hasattr(self, 'current_wallet') and self.current_wallet:
                # Securely overwrite sensitive data
                if 'private_key' in self.current_wallet:
                    # Overwrite with random data before deletion
                    self.current_wallet['private_key'] = secrets.token_hex(32)
                    del self.current_wallet['private_key']

                if 'wif_key' in self.current_wallet:
                    self.current_wallet['wif_key'] = 'x' * 52
                    del self.current_wallet['wif_key']

                # Clear the entire wallet data
                self.current_wallet.clear()
                self.current_wallet = None

            # Force garbage collection
            gc.collect()

            # Additional security: create and overwrite dummy variables
            dummy_data = [secrets.token_bytes(32) for _ in range(10)]
            for data in dummy_data:
                # Overwrite each byte
                for i in range(len(data)):
                    data = data[:i] + b'\x00' + data[i + 1:]
            del dummy_data

            gc.collect()

        except Exception as e:
            print(f"\033[90m⚠️  Memory cleanup warning: {e}\033[0m")

    def ask_private_key_display(self):
        """Ask user if they want to display private keys with security warnings"""
        print(f"\n\033[91m🔐 PRIVATE KEY SECURITY WARNING:\033[0m")
        print(f"\033[93m   • Private keys give FULL control over your Bitcoin\033[0m")
        print(f"\033[93m   • Ensure NO ONE can see your screen\033[0m")
        print(f"\033[93m   • Never share, screenshot, or email private keys\033[0m")
        print(f"\033[93m   • Make secure offline backups only\033[0m")

        choice = input(
            "\n\033[95mDo you understand the risks and want to display private keys? (y/N): \033[0m").strip().lower()
        return choice == 'y'

    def display_private_keys_securely(self, wallet_info):
        """Display private keys with additional security measures"""
        if not wallet_info:
            print("\033[91m❌ No wallet data available\033[0m")
            return

        print(f"\n\033[92m🔐 PRIVATE KEYS (KEEP SECRET!):\033[0m")
        print(f"\033[94m{'=' * 80}\033[0m")
        print(f"\033[93mPrivate key (hex):\033[0m")
        print(f"\033[97m{wallet_info['private_key']}\033[0m")
        print(f"\n\033[93mCompressed WIF key:\033[0m")
        print(f"\033[97m{wallet_info['wif_key']}\033[0m")
        print(f"\033[94m{'=' * 80}\033[0m")

        # Show additional security reminder
        print(f"\n\033[91m⚠️  SECURITY REMINDER:\033[0m")
        print(f"\033[93m   • Write these down on paper and store securely\033[0m")
        print(f"\033[93m   • Never store digitally without encryption\033[0m")
        print(f"\033[93m   • These keys will be cleared from memory soon\033[0m")

        self.private_key_displayed = True

    def generate_private_key(self):
        """Generate secure private key using cryptographically secure RNG"""
        max_attempts = 10
        for attempt in range(max_attempts):
            try:
                # Generate 32 random bytes using cryptographically secure RNG
                private_key = secrets.token_bytes(32)

                # Additional validation to ensure key is within curve range
                n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
                private_key_int = int.from_bytes(private_key, 'big')

                if 1 <= private_key_int < n:
                    return private_key

                # If key is invalid, try again
                print(f"\033[90m⚠️  Attempt {attempt + 1}: Generated invalid key, retrying...\033[0m")

            except Exception as e:
                print(f"\033[90m⚠️  Attempt {attempt + 1}: Error in key generation: {e}\033[0m")

        # If we reach here, all attempts failed
        raise Exception(f"❌ Failed to generate valid private key after {max_attempts} attempts")

    def private_key_to_wif(self, private_key, compressed=True):
        """Convert private key to WIF format with proper error handling"""
        try:
            # Add version byte (0x80 for mainnet)
            versioned_key = b'\x80' + private_key

            # Add compression flag if needed
            if compressed:
                versioned_key += b'\x01'

            # Double SHA256 hash
            first_hash = hashlib.sha256(versioned_key).digest()
            second_hash = hashlib.sha256(first_hash).digest()

            # Add checksum (first 4 bytes)
            checksum = second_hash[:4]

            # Combine and encode as base58
            wif_key = base58.b58encode(versioned_key + checksum)
            return wif_key.decode('ascii')
        except Exception as e:
            print(f"\033[91m❌ Error converting to WIF: {e}\033[0m")
            return None

    def private_key_to_public_key(self, private_key, compressed=True):
        """Convert private key to public key with proper error handling"""
        try:
            # Validate private key length
            if len(private_key) != 32:
                raise ValueError("Private key must be 32 bytes")

            # Create signing key
            sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)

            # Get verifying key (public key)
            vk = sk.get_verifying_key()

            if compressed:
                # Compressed public key format
                x = vk.pubkey.point.x()
                y = vk.pubkey.point.y()
                if y % 2 == 0:
                    return b'\x02' + x.to_bytes(32, 'big')
                else:
                    return b'\x03' + x.to_bytes(32, 'big')
            else:
                # Uncompressed public key format
                return b'\x04' + vk.to_string()

        except Exception as e:
            print(f"\033[91m❌ Error generating public key: {e}\033[0m")
            return None

    def hrp_expand(self, hrp):
        """Expand the HRP into values for checksum computation"""
        try:
            result = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
            return result
        except Exception as e:
            print(f"\033[91m❌ Error in HRP expansion: {e}\033[0m")
            return []

    def polymod(self, values):
        """Compute the Bech32 checksum"""
        try:
            generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
            chk = 1
            for value in values:
                top = chk >> 25
                chk = (chk & 0x1ffffff) << 5 ^ value
                for i in range(5):
                    chk ^= generator[i] if ((top >> i) & 1) else 0
            return chk
        except Exception as e:
            print(f"\033[91m❌ Error in polymod calculation: {e}\033[0m")
            return 0

    def create_checksum(self, hrp, data):
        """Compute the checksum values with explicit parentheses"""
        try:
            values = self.hrp_expand(hrp) + data
            polymod = self.polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
            return [(polymod >> (5 * (5 - i))) & 31 for i in range(6)]
        except Exception as e:
            print(f"\033[91m❌ Error creating checksum: {e}\033[0m")
            return [0, 0, 0, 0, 0, 0]

    def convertbits(self, data, frombits, tobits, pad=True):
        """General power-of-2 base conversion (standard implementation)"""
        try:
            acc = 0
            bits = 0
            ret = []
            maxv = (1 << tobits) - 1
            max_acc = (1 << (frombits + tobits - 1)) - 1

            for value in data:
                if value < 0 or (value >> frombits):
                    return None
                acc = ((acc << frombits) | value) & max_acc
                bits += frombits
                while bits >= tobits:
                    bits -= tobits
                    ret.append((acc >> bits) & maxv)

            if pad:
                if bits:
                    ret.append((acc << (tobits - bits)) & maxv)
            elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
                return None

            return ret
        except Exception as e:
            print(f"\033[91m❌ Error converting bits: {e}\033[0m")
            return None

    def public_key_to_p2pkh_address(self, public_key):
        """Convert public key to P2PKH address (starts with 1)"""
        try:
            # Проверяем что публичный ключ сжатый
            if len(public_key) != 33:
                raise ValueError("P2PKH requires compressed public key (33 bytes)")

            # SHA256 hash of public key
            sha256_hash = hashlib.sha256(public_key).digest()

            # RIPEMD160 hash of SHA256
            ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()

            # Add version byte for P2PKH (0x00)
            versioned_hash = b'\x00' + ripemd160_hash

            # Double SHA256 for checksum
            first_checksum = hashlib.sha256(versioned_hash).digest()
            second_checksum = hashlib.sha256(first_checksum).digest()

            # Add checksum and encode
            address_bytes = versioned_hash + second_checksum[:4]
            return base58.b58encode(address_bytes).decode('ascii')
        except Exception as e:
            print(f"\033[91m❌ Error generating P2PKH address: {e}\033[0m")
            return None

    def public_key_to_p2sh_p2wpkh_address(self, public_key):
        """Convert public key to P2SH-P2WPKH address (starts with 3)"""
        try:
            # Проверяем что публичный ключ сжатый
            if len(public_key) != 33:
                raise ValueError("P2SH-P2WPKH requires compressed public key (33 bytes)")

            # First create the witness program for P2WPKH
            sha256_hash = hashlib.sha256(public_key).digest()
            ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()

            # Witness program: version 0 + RIPEMD160 hash (20 bytes)
            witness_program = b'\x00\x14' + ripemd160_hash

            # SHA256 + RIPEMD160 of witness program for P2SH
            sha256_witness = hashlib.sha256(witness_program).digest()
            ripemd160_witness = hashlib.new('ripemd160', sha256_witness).digest()

            # Add version byte for P2SH (0x05)
            versioned_hash = b'\x05' + ripemd160_witness

            # Double SHA256 for checksum
            first_checksum = hashlib.sha256(versioned_hash).digest()
            second_checksum = hashlib.sha256(first_checksum).digest()

            # Add checksum and encode
            address_bytes = versioned_hash + second_checksum[:4]
            return base58.b58encode(address_bytes).decode('ascii')
        except Exception as e:
            print(f"\033[91m❌ Error generating P2SH-P2WPKH address: {e}\033[0m")
            return None

    def public_key_to_bech32_address(self, public_key, witness_version=0):
        """Convert public key to Bech32 address (P2WPKH)"""
        try:
            # Проверяем что публичный ключ сжатый
            if len(public_key) != 33:
                raise ValueError("Bech32 requires compressed public key (33 bytes)")

            # SHA256 + RIPEMD160 of public key
            sha256_hash = hashlib.sha256(public_key).digest()
            ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()

            # Convert to 5-bit words
            converted = self.convertbits(ripemd160_hash, 8, 5)
            if not converted:
                raise ValueError("Failed to convert bits for Bech32")

            data = [witness_version] + converted

            # Create checksum
            checksum = self.create_checksum('bc', data)

            # Combine and encode
            combined = data + checksum
            bech32_address = 'bc1' + ''.join([self.BECH32_ALPHABET[x] for x in combined])
            return bech32_address
        except Exception as e:
            print(f"\033[91m❌ Error generating Bech32 address: {e}\033[0m")
            return None

    def get_address_type_choice(self):
        """Get address type choice from user"""
        while True:
            print()
            self.show_address_types()
            choice = input("\n\033[95m🎯 Enter address type (1, 3 or bc): \033[0m").strip().lower()
            if choice in self.address_types:
                return choice
            else:
                print("\033[91m❌ Error: Please choose 1, 3 or bc\033[0m")

    def check_balance_and_transactions(self, address: str) -> Dict:
        """Check balance and transactions using blockchain.com API"""
        print(f"\n\033[93m🔍 Checking blockchain data for address...\033[0m")
        print(f"\033[90m⏳ Connecting to blockchain API...\033[0m")

        try:
            # Using blockchain.info API
            base_url = f"https://blockchain.info/rawaddr/{address}"
            response = requests.get(base_url, timeout=15)

            if response.status_code == 200:
                data = response.json()

                # Display results in beautiful format
                self.display_blockchain_info(data, address)
                return data
            elif response.status_code == 429:
                print(f"\033[91m❌ Error: Rate limit exceeded. Please try again later.\033[0m")
                return None
            else:
                print(f"\033[91m❌ Error: Unable to fetch data (HTTP {response.status_code})\033[0m")
                return None

        except requests.exceptions.Timeout:
            print(f"\033[91m❌ Error: Request timeout. Please check your internet connection.\033[0m")
            return None
        except requests.exceptions.RequestException as e:
            print(f"\033[91m❌ Network error: {e}\033[0m")
            return None
        except json.JSONDecodeError:
            print(f"\033[91m❌ Error: Invalid response from API\033[0m")
            return None

    def display_blockchain_info(self, data: Dict, address: str):
        """Display blockchain information in beautiful format"""
        print(f"\n\033[92m✅ Blockchain Data Retrieved Successfully!\033[0m")
        print(f"\033[94m{'=' * 80}\033[0m")

        # Address info
        print(f"\033[96m📍 Address:\033[0m \033[97m{address}\033[0m")
        print(f"\033[96m📊 Total Transactions:\033[0m \033[97m{data.get('n_tx', 0)}\033[0m")

        # Balance info
        total_received = data.get('total_received', 0) / 100000000
        total_sent = data.get('total_sent', 0) / 100000000
        final_balance = data.get('final_balance', 0) / 100000000

        print(f"\n\033[95m💰 Balance Information:\033[0m")
        print(f"   \033[93mTotal Received:\033[0m \033[97m{total_received:.8f} BTC\033[0m")
        print(f"   \033[93mTotal Sent:\033[0m \033[97m{total_sent:.8f} BTC\033[0m")
        print(f"   \033[92mFinal Balance:\033[0m \033[97m{final_balance:.8f} BTC\033[0m")

        # Recent transactions
        transactions = data.get('txs', [])[:5]  # Show last 5 transactions
        if transactions:
            print(f"\n\033[95m📋 Recent Transactions (Last {len(transactions)}):\033[0m")
            for i, tx in enumerate(transactions, 1):
                print(f"\n   \033[96mTransaction #{i}:\033[0m")
                print(f"   \033[90mHash:\033[0m \033[97m{tx['hash'][:20]}...\033[0m")
                print(f"   \033[90mTime:\033[0m \033[97m{self.format_timestamp(tx.get('time', 0))}\033[0m")
                print(f"   \033[90mConfirmations:\033[0m \033[97m{tx.get('result', 0)}\033[0m")
        else:
            print(f"\n\033[93m📭 No transactions found for this address\033[0m")

        print(f"\033[94m{'=' * 80}\033[0m")

    def format_timestamp(self, timestamp: int) -> str:
        """Format UNIX timestamp to readable date"""
        if timestamp == 0:
            return "Unknown"
        try:
            return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(timestamp))
        except:
            return "Invalid timestamp"

    def generate_wallet(self):
        """Main wallet generation function"""
        # Print beautiful banner
        self.print_banner()

        # Show security warnings
        self.print_security_warnings()

        # Choose address type
        address_type = self.get_address_type_choice()
        print(f"\n\033[92m✅ Selected address type: {self.address_types[address_type]}\033[0m")

        # Generate private key
        print(f"\033[90m⏳ Generating secure private key...\033[0m")
        private_key = self.generate_private_key()
        private_key_hex = private_key.hex()

        # Generate WIF key (compressed)
        print(f"\033[90m⏳ Generating WIF key...\033[0m")
        wif_key = self.private_key_to_wif(private_key, compressed=True)
        if not wif_key:
            return None

        # Generate compressed public key
        print(f"\033[90m⏳ Generating public key...\033[0m")
        compressed_public_key = self.private_key_to_public_key(private_key, compressed=True)
        if not compressed_public_key:
            return None
        compressed_public_key_hex = compressed_public_key.hex()

        # Generate address based on type with proper naming
        print(f"\033[90m⏳ Generating address...\033[0m")
        if address_type == "1":
            compressed_address = self.public_key_to_p2pkh_address(compressed_public_key)
            address_display_name = "P2PKH Address"
        elif address_type == "3":
            compressed_address = self.public_key_to_p2sh_p2wpkh_address(compressed_public_key)
            address_display_name = "P2SH-P2WPKH Address"
        else:  # "bc"
            compressed_address = self.public_key_to_bech32_address(compressed_public_key)
            address_display_name = "Bech32 (P2WPKH) Address"

        if not compressed_address:
            print(f"\033[91m❌ Error: Failed to generate address\033[0m")
            return None

        # Store current wallet info
        self.current_wallet = {
            'private_key': private_key_hex,
            'wif_key': wif_key,
            'public_key': compressed_public_key_hex,
            'address': compressed_address,
            'address_type': address_type,
            'address_display_name': address_display_name
        }

        # Display results (public info only)
        print(f"\n\033[92m🔐 Wallet Generated Successfully!\033[0m")
        print(f"\033[94m{'=' * 80}\033[0m")
        print(f"\033[93mCompressed public key:\033[0m")
        print(f"\033[97m{compressed_public_key_hex}\033[0m")
        print(f"\n\033[93m{address_display_name}:\033[0m")
        print(f"\033[97m{compressed_address}\033[0m")
        print(f"\033[94m{'=' * 80}\033[0m")

        # Inform user about private keys
        print(f"\n\033[93m🔒 Private keys are securely stored in memory\033[0m")
        print(f"\033[93m   Use option '2' to display them securely when ready\033[0m")

        return self.current_wallet

    def main_loop(self):
        """Main program loop with menu"""
        try:
            while True:
                # Generate initial wallet
                wallet = self.generate_wallet()
                if not wallet:
                    print(f"\033[91m❌ Failed to generate wallet. Please try again.\033[0m")
                    continue

                # Show main menu
                while True:
                    self.show_main_menu()
                    choice = input("\n\033[95m🎯 Enter your choice (1-4): \033[0m").strip()

                    if choice == "1":
                        # Check balance and transactions
                        if self.current_wallet:
                            print(f"\n\033[93m⚠️  Security Notice:\033[0m")
                            print(f"\033[93m   • This requires internet connection\033[0m")
                            print(f"\033[93m   • Your address will be sent to blockchain.com API\033[0m")
                            print(f"\033[93m   • No private keys are shared\033[0m")
                            confirm = input("\n\033[95mContinue? (y/N): \033[0m").strip().lower()
                            if confirm == 'y':
                                self.check_balance_and_transactions(self.current_wallet['address'])
                            else:
                                print(f"\033[90mOperation cancelled.\033[0m")
                        else:
                            print("\033[91m❌ No wallet generated yet!\033[0m")

                    elif choice == "2":
                        # Show private keys securely
                        if self.current_wallet:
                            if self.ask_private_key_display():
                                self.display_private_keys_securely(self.current_wallet)
                            else:
                                print(f"\033[90mPrivate keys not displayed.\033[0m")
                        else:
                            print("\033[91m❌ No wallet generated yet!\033[0m")

                    elif choice == "3":
                        # Generate new wallet - clear memory first
                        print(f"\n\033[92m🔄 Generating new wallet...\033[0m")
                        print(f"\033[90m🧹 Clearing previous wallet from memory...\033[0m")
                        self.secure_memory_cleanup()
                        break  # Break inner loop to generate new wallet

                    elif choice == "4":
                        # Exit program with secure cleanup
                        print(f"\n\033[92m👋 Thank you for using Bitcoin Wallet Generator!\033[0m")
                        print(f"\033[92m📧 Created by: {self.author}\033[0m")
                        print(f"\033[93m💰 Donate BTC: {self.donate_address}\033[0m")
                        print(f"\033[90m🧹 Securely clearing memory...\033[0m")
                        self.secure_memory_cleanup()
                        print(f"\033[92m🔒 All private keys cleared from memory\033[0m")
                        print(f"\033[92m🚪 Exiting program...\033[0m")
                        return

                    else:
                        print("\033[91m❌ Invalid choice! Please enter 1, 2, 3 or 4\033[0m")

        finally:
            # Ensure memory is cleaned up even if program crashes
            self.secure_memory_cleanup()


# Main program
if __name__ == "__main__":
    try:
        print(f"\033[90m🚀 Starting Bitcoin Wallet Generator v1.0 (Secure Edition)...\033[0m")
        wallet_gen = BitcoinWalletGenerator()
        wallet_gen.main_loop()
    except KeyboardInterrupt:
        print(f"\n\n\033[92m👋 Program interrupted by user. Goodbye!\033[0m")
        print(f"\033[92m📧 Created by: {wallet_gen.author}\033[0m")
        print(f"\033[93m💰 Donate BTC: {wallet_gen.donate_address}\033[0m")
        wallet_gen.secure_memory_cleanup()
    except Exception as e:
        print(f"\n\033[91m❌ Unexpected error: {e}\033[0m")
        print(f"\033[90mPlease report this issue to the developer.\033[0m")
        wallet_gen.secure_memory_cleanup()
    finally:
        print(f"\n\033[90m🔒 Program terminated securely.\033[0m")