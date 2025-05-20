from web3 import Web3
import json

class BlockchainLogger:
    def __init__(self, contract_address, contract_abi, provider_url="http://127.0.0.1:8545"):
        self.w3 = Web3(Web3.HTTPProvider("http://ganache:8545"))
        print("✅ Using Ethereum RPC:", self.w3.provider.endpoint_uri)

        self.contract = self.w3.eth.contract(address=contract_address, abi=contract_abi)
        self.account = self.w3.eth.accounts[0]
    
    def log_file_share(self, file_hash):
        try:
            tx_hash = self.contract.functions.logFileShare(file_hash).transact({
                'from': self.account,
                'gas': 500000
            })
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            print(f"Transaction logged. Hash: {receipt['transactionHash'].hex()}")
            return True
        except Exception as e:
            print(f"Error logging transaction: {e}")
            return False
    
    def get_logs_count(self):
        return self.contract.functions.getLogsCount().call()
    
    def get_log(self, index):
        return self.contract.functions.getLog(index).call()

# Usage example
if __name__ == "__main__":
    # Load contract ABI
    with open('../build/contracts/FileShareLogger.json') as f:
        contract_json = json.load(f)
        contract_abi = contract_json['abi']
    
    contract_address = "0xCfEB869F69431e42cdB54A4F4f105C19C080A601" # Replace with deployed contract address
    logger = BlockchainLogger(contract_address, contract_abi)
    
    # Log a file share
    logger.log_file_share("sample_file_hash")
