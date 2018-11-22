pragma solidity ^0.4.24;

import "./ERC777.sol";
import "openzeppelin-solidity/contracts/access/roles/MinterRole.sol";

/**
 * @title ERC777Mintable
 * @dev ERC777 minting logic
 */
contract ERC777Mintable is ERC777, MinterRole {
  /**
   * [NOT MANDATORY FOR ERC777 STANDARD]
   * @dev Mint the amout of tokens for the recipient 'to'.
   * @param to Token recipient.
   * @param amount Number of tokens minted.
   * @param data Information attached to the minting, and intended for the recipient (to).
   * @return A boolean that indicates if the operation was successful.
   */
  function mint(address to, uint256 amount, bytes data)
    external
    isValidCertificate(data)
    onlyMinter
    returns (bool)
  {
    _mint(msg.sender, to, amount, data, "");

    return true;
  }
}