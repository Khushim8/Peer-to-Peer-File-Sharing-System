# P2P File Sharing System with Blockchain Logging

This project implements a peer-to-peer file sharing system with blockchain logging for all upload/download events using Docker, Flask, Truffle, and Web3.py.


## Project Structure

```
p2p/
├── blockchain_logger/        # Python code for logging events to blockchain
├── build/contracts/          # Compiled contract JSONs from Truffle
├── contracts/                # Solidity smart contracts
├── files1/, files2/          # Mounted folders used by peer1 and peer2
├── migrations/               # Truffle migration scripts
├── peer_client/              # Dockerized Python peer client implementation
├── Tracker_server/           # Flask-based tracker for peer registration and file lookup
├── docker-compose.yml        # Docker composition for all services
├── truffle-config.js         # Truffle project config
└── readme.txt                # This file
```

---

## 🔧 Dependencies

- Docker & Docker Compose
- Python 3.9 (used in containers)
- Node.js & Truffle (for smart contract deployment)
- Ganache CLI (Ethereum local chain)
- MySQL 8.0 (Tracker DB)
- Flask, SQLAlchemy, Web3.py (Python)
- Solidity ^0.8.0 (Smart contract)

---

## Environment Setup

### Clean Docker Environment

```bash
docker-compose down --volumes --remove-orphans
```

### Build & Start All Services

```bash
docker-compose up -d --build
```

### Run Contract Migrations

```bash
truffle migrate --reset --network development
```

Copy the deployed contract address and paste it in `client.py` under:
```python
contract_address = "0x..."
```

---

## Running the System

### Upload File from Peer1

```bash
docker exec -it p2p-peer1-1 bash
python3 client.py
```

Menu:
```
1. Upload file
Path: /app/files/test.txt
```

### Download from Peer2

```bash
docker exec -it p2p-peer2-1 bash
python3 client.py
```

Menu:
```
2. Download file
Enter hash from Peer1 upload
```

### View Logs

Choose menu option `5` in any peer:
```
5. View blockchain logs
Cloud Resources: None. All components are run locally via Docker and Ganache CLI.

Team Members & Contributions

### Sheiley Patel
- Designed the tracker server and ensured seamless file transfer between peers.
- Contributed to system architecture, especially flow control and data registration.
- Coordinated end-to-end system behavior.

### Reshma Merin Thomas
- Developed the Ethereum smart contract for immutable event logging.
- Integrated blockchain logging into the peer client.
- Focused on linking blockchain events with file activity.

### Khushi Mahajan
- Implemented core components of the tracker and file transfer protocol.
- Contributed to Ethereum smart contract integration and testing.
- Helped containerize and orchestrate the system using Docker.


Sheiley Patel – Docker Compose setup, smart contract development, and blockchain integration
Reshma Merin Thomas – Peer-to-peer architecture and networking logic
Khushi Mahajan – Tracker server, database schema, and file registration

Summary Commands

```bash
# Start everything
docker-compose up -d --build

# Contract migration
truffle migrate --reset --network development

# Exec into peer and run client
docker exec -it p2p-peer1-1 bash
python3 client.py