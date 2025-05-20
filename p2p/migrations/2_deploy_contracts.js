const FileShareLogger = artifacts.require("FileShareLogger");

module.exports = function(deployer) {
  deployer.deploy(FileShareLogger);
};

