/*
 * This code has not been reviewed.
 * Do not use or deploy this code before reviewing it personally first.
 */
pragma solidity ^0.5.12;

import "./token/ERC20/ERC1400ERC20.sol";

/**
 * @title ERC1400
 * @dev ERC1400 logic
 */
contract MWT is ERC1400ERC20 {

  // Some actions might need the actors to be whitelisted in the future
  bool needWhitelisting = false;

  /**
  * [ERC1400ERC20 CONSTRUCTOR]
  * @dev Initialize ERC71400ERC20 and CertificateController parameters + register
  * the contract implementation in ERC1820Registry.
  * @param name Name of the token.
  * @param symbol Symbol of the token.
  * @param granularity Granularity of the token.
  * @param controllers Array of initial controllers.
  * @param certificateSigner Address of the off-chain service which signs the
  * conditional ownership certificates required for token transfers, issuance,
  * redemption (Cf. CertificateController.sol).
  */
  constructor(
      string memory name,
      string memory symbol,
      uint256 granularity,
      address[] memory controllers,
      address certificateSigner,
      bytes32[] memory tokenDefaultPartitions
  )
      public
      ERC1400ERC20(name, symbol, granularity, controllers, certificateSigner, tokenDefaultPartitions)
  {
  }

  /**
   * @dev Add this to a function that might reequire involved actors to be whitelisted in the future
   */
  modifier mayNeedWhitelisting(address sender, address recipient) {
    if (needWhitelisting) {
      require(_whitelisted[sender], "A5"); //Transfer Blocked - Sender not eligible
      require(_whitelisted[recipient], "A6"); //Transfer Blocked - Receiver not eligible
    }
    _;
  }

  /**
   * === Overrides ERC20 function ===
   * @dev Moves perpetual bonds.
   * @param sender The address from which the tokens should be withdrawn
   * @param recipient The address to which the tokens should be deposit
   * @param amount How many tokens to transfer
   */
  function _transfer(address sender, address recipient, uint256 amount) internal {
    require(sender != address(0), "A8"); //Transfer Blocked - Token restriction
    require(recipient != address(0), "A8"); //Transfer Blocked - Token restriction
    require(_defaultPartitions.length != 0, "A8"); // Transfer Blocked - Token restriction

    bytes32 perpetualPartition = _defaultPartitions[0];

    require(_balanceOfByPartition[sender][perpetualPartition] >= amount, "A4"); // Transfer Blocked - Sender balance insufficient

    _removeTokenFromPartition(sender, perpetualPartition, amount);
    _transferWithData(perpetualPartition, sender, sender, recipient, amount, "", "", false);
    _addTokenToPartition(recipient, perpetualPartition, amount);
  }

  /**
   * @dev Enable or disable whitelisting requirement
   * @param needWhitelist True to enable whitelisting requirement
   */
  function setNeedWhitelisting(bool needWhitelist) external onlyOwner {
    needWhitelisting = needWhitelist;
  }

  /**
   * === Overrides ERC1400raw function ===
   * @dev Get the perpetual balance of the account with address 'tokenHolder', overrides ERC20 and ERC1400Raw balanceOf functions.
   * @param tokenHolder Address for which the perpetual balance is returned.
   * @return Amount of token Perpetual (default partition) held by 'tokenHolder' in the token contract.
   */
  function balanceOf(address tokenHolder) external view returns (uint256) {
    bytes32 perpetualPartition = _defaultPartitions[0];
    return _balanceOfByPartition[tokenHolder][perpetualPartition];
  }

  /**
   * === Overrides ERC20 function ===
   * @dev Transfer token for a specified address.
   * @param to The address to transfer to.
   * @param value The value to be transferred.
   * @return A boolean that indicates if the operation was successful.
   */
  function transfer(address to, uint256 value) external mayNeedWhitelisting(msg.sender, to) returns (bool) {
    _transfer(msg.sender, to, value);
    return true;
  }

  /**
   * @dev Remove the right to mint new tokens.
   */
  function removeMinter(address minter) external onlyOwner {
    _removeMinter(minter);
  }

  /**
   * === Overrides MinterRole.sol function ===
   * @dev Add the right to mint new tokens.
   */
  function addMinter(address account) public onlyOwner {
    _addMinter(account);
  }

  /**
   * @dev Getter to check if whitelist is neeeded to use ERC20-like perpetual bonds.
   */
  function needWhitelist() external view returns (bool) {
    return needWhitelisting;
  }
}
