import socket
import threading
import hashlib
import os
import json
import requests
import sys
from blockchain_logger.blockchain_logger import BlockchainLogger

TRACKER_URL = os.getenv("TRACKER_URL", "http://tracker:5000")
CHUNK_SIZE = 4096
FILES_DIR = "/app/files"  # Mounted volume

class PeerClient:
    def __init__(self, host='0.0.0.0', port=6000):
        self.host = host
        self.port = port
        self.files = {}
        self.peer_id = None

        # Load smart contract ABI and address
        abi_path = '/p2p/build/contracts/FileShareLogger.json'
        with open(abi_path) as f:
            contract_json = json.load(f)
            contract_abi = contract_json['abi']

        contract_address = "0xCfEB869F69431e42cdB54A4F4f105C19C080A601"
        self.logger = BlockchainLogger(contract_address, contract_abi)

    def start(self):
        self.register_with_tracker()
        server_thread = threading.Thread(target=self.start_server, daemon=True)
        server_thread.start()
        self.show_menu()

    def register_with_tracker(self):
        actual_ip = socket.gethostbyname(socket.gethostname())
        try:
            response = requests.post(f"{TRACKER_URL}/register_peer",
                                     json={'ip': actual_ip, 'port': self.port})
            print("Tracker response:", response.status_code, response.text)
            data = response.json()
            self.peer_id = data['peer_id']
            print(f"[✓] Registered with tracker as Peer {self.peer_id}")
        except Exception as e:
            print("❌ Failed to register with tracker:", e)
            sys.exit(1)

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        print(f"[🚀] File server listening on {self.host}:{self.port}")

        while True:
            client_socket, _ = server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket,), daemon=True).start()

    def handle_client(self, client_socket):
        try:
            file_hash = client_socket.recv(1024).decode().strip()
            if file_hash in self.files:
                file_path = self.files[file_hash]
            else:
                # fallback: look in /app/files directory
                file_path = os.path.join(FILES_DIR, file_hash)
                if not os.path.exists(file_path):
                    client_socket.sendall(b"FILE_NOT_FOUND")
                    return

            file_size = os.path.getsize(file_path)
            client_socket.sendall(b"FILE_FOUND")
            client_socket.sendall(f"{file_size}\n".encode())

            with open(file_path, "rb") as f:
                while chunk := f.read(CHUNK_SIZE):
                    client_socket.sendall(chunk)
            print(f"[✓] Sent file {file_path}")

        except Exception as e:
            print(f"[!] Error handling download: {e}")
        finally:
            client_socket.close()

    def upload_file(self, file_path):
        if not os.path.exists(file_path):
            print("❌ File does not exist!")
            return

        file_name = os.path.basename(file_path)
        file_hash = hashlib.sha256(file_name.encode()).hexdigest()

        try:
            response = requests.post(f"{TRACKER_URL}/register_file",
                                     json={'file_name': file_name, 'peer_id': self.peer_id})
            data = response.json()

            if data['status'] == 'success':
                self.files[file_hash] = file_path
                print(f"[↑] Uploaded. File Hash: {file_hash}")
                if self.logger.log_file_share(file_hash):
                    print("📦 Upload logged on blockchain.")
            else:
                print("❌ Failed to register file with tracker")
        except Exception as e:
            print("❌ Error during file registration:", e)

    def download_file(self, file_hash):
        try:
            response = requests.get(f"{TRACKER_URL}/search", params={'file_hash': file_hash})
            data = response.json()

            if data['status'] != 'success' or not data['peers']:
                print("❌ File not found or no peers available.")
                return

            file_name = data['file_name']
            for peer in data['peers']:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((peer['ip'], peer['port']))
                    s.sendall(file_hash.encode())

                    header = s.recv(1024).decode().strip()
                    if header != "FILE_FOUND":
                        print(f"[!] Peer responded: {header}")
                        s.close()
                        continue

                    file_size = int(s.recv(1024).decode().strip())
                    os.makedirs("downloads", exist_ok=True)
                    download_path = f"downloads/{file_name}"

                    with open(download_path, "wb") as f:
                        received = 0
                        while received < file_size:
                            chunk = s.recv(CHUNK_SIZE)
                            if not chunk:
                                break
                            f.write(chunk)
                            received += len(chunk)

                    print(f"[✓] File downloaded to {download_path}")
                    s.close()

                    if self.logger.log_file_share(file_hash):
                        print("📦 Download logged on blockchain.")
                    return
                except Exception as e:
                    print(f"[!] Failed from {peer['ip']}:{peer['port']}: {e}")
                    continue

            print(" Download failed from all peers.")
        except Exception as e:
            print(" Error contacting tracker:", e)

    def show_menu(self):
        while True:
            print("\n=== P2P File Sharing ===")
            print("1. Upload file")
            print("2. Download file")
            print("3. List shared files")
            print("4. Exit")
            print("5. View blockchain logs")
            choice = input("Enter choice: ")
            if choice == '1':
                path = input("Enter file path to upload: ")
                self.upload_file(path)
            elif choice == '2':
                file_hash = input("Enter file hash to download: ")
                self.download_file(file_hash)
            elif choice == '3':
                for file_hash, path in self.files.items():
                    print(f"Hash: {file_hash} → {path}")
            elif choice == '4':
                sys.exit(0)
            elif choice == '5':
                count = self.logger.get_logs_count()
                print(f"Total logs: {count}")
                for i in range(count):
                    sender, file_hash, ts = self.logger.get_log(i)
                    print(f"{i+1}. Sender: {sender}, File Hash: {file_hash}, Timestamp: {ts}")
            else:
                print("Invalid choice")

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 6000
    client = PeerClient(port=port)
    client.start()
