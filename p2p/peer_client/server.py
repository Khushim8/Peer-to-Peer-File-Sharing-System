import socket
import threading
import os

# Folder where uploaded files are stored
FILES_DIR = "/app/files"

def handle_client(conn, addr):
    print(f"[+] Connected by {addr}")
    try:
        file_hash = conn.recv(1024).decode().strip()
        print(f"[>] Request for file hash: {file_hash}")
        file_path = os.path.join(FILES_DIR, file_hash)

        if not os.path.exists(file_path):
            print("[!] File not found")
            conn.sendall(b"FILE_NOT_FOUND")
        else:
            conn.sendall(b"FILE_FOUND")
            with open(file_path, "rb") as f:
                while chunk := f.read(1024):
                    conn.sendall(chunk)
            print(f"[✓] Sent file {file_path}")
    except Exception as e:
        print(f"[!] Error handling client: {e}")
    finally:
        conn.close()

def start_file_server():
    host = "0.0.0.0"
    port = 6000

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"[🚀] File server listening on {host}:{port}")

    while True:
        conn, addr = server_socket.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        thread.start()

if __name__ == "__main__":
    start_file_server()
