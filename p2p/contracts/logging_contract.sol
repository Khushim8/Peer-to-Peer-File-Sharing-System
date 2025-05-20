// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FileShareLogger {
    struct FileLog {
        address sender;
        string fileHash;
        uint256 timestamp;
    }
    
    FileLog[] public logs;
    
    event FileShared(address indexed sender, string fileHash, uint256 timestamp);
    
    function logFileShare(string memory _fileHash) public {
        FileLog memory newLog = FileLog({
            sender: msg.sender,
            fileHash: _fileHash,
            timestamp: block.timestamp
        });
        
        logs.push(newLog);
        emit FileShared(msg.sender, _fileHash, block.timestamp);
    }
    
    function getLogsCount() public view returns (uint256) {
        return logs.length;
    }
    
    function getLog(uint256 index) public view returns (address, string memory, uint256) {
        require(index < logs.length, "Index out of bounds");
        FileLog memory log = logs[index];
        return (log.sender, log.fileHash, log.timestamp);
    }
}
