pragma solidity ^0.5.12;


contract CertificateController {

  // Address used by off-chain controller service to sign certificate
  mapping(address => bool) internal _certificateSigners;

  // A nonce used to ensure a certificate can be used only once
  mapping(address => uint256) internal _checkCount;

  event Checked(address sender);

  constructor(address _certificateSigner) public {
    _setCertificateSigner(_certificateSigner, true);
  }

  /**
   * @dev Modifier to protect methods with certificate control
   */
  modifier isValidCertificate(bytes memory data) {

    require(_certificateSigners[msg.sender] || _checkCertificate(data, msg.sig, bytes32(_checkCount[msg.sender])), "A3: Transfer Blocked - Sender lockup period not ended");

    _checkCount[msg.sender] += 1; // Increment sender check count

    emit Checked(msg.sender);
    _;
  }

  /**
   * @dev Get number of transations already sent to this contract by the sender
   * @param sender Address whom to check the counter of.
   * @return uint256 Number of transaction already sent to this contract.
   */
  function checkCount(address sender) external view returns (uint256) {
    return _checkCount[sender];
  }

  /**
   * @dev Get certificate signer authorization for an operator.
   * @param operator Address whom to check the certificate signer authorization for.
   * @return bool 'true' if operator is authorized as certificate signer, 'false' if not.
   */
  function certificateSigners(address operator) external view returns (bool) {
    return _certificateSigners[operator];
  }

  /**
   * @dev Set signer authorization for operator.
   * @param operator Address to add/remove as a certificate signer.
   * @param authorized 'true' if operator shall be accepted as certificate signer, 'false' if not.
   */
  function _setCertificateSigner(address operator, bool authorized) internal {
    require(operator != address(0), "Action Blocked - Not a valid address");
    _certificateSigners[operator] = authorized;
  }

  /**
   * @dev Checks if a certificate is correct
   * @param signature The signature for the nonce and the functionID (contains v, r, s)
   * @param function_id The id of the function which use is restricted to certificate owners
   * @param nonce A nonce signed along with the functionID so that the certificate cannot be used twice
   */
   function _checkCertificate(bytes memory signature, bytes4 function_id, bytes32 nonce) internal view returns(bool) {
       require(signature.length == 65, "A valid signature containing (v, r, s) is needed.");

       // ecrecover() expects a message starting with that.. 
       bytes32 tmp_hash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", function_id, nonce));
       uint8 v = uint8(signature[0]);
       bytes32 r = bytes32(0);
       bytes32 s = bytes32(0);

       // r is the [1:33] elements of the signature and s the [33:65], so we add 0x20 + 1 to pass the
       // array size (on 32 bytes) + the first element, and another 0x20 to get to the 33th element.
       assembly {
            r := mload(add(signature, 0x21))
            s := mload(add(signature, 0x41))
       }
       assert(r != bytes32(0) && s != bytes32(0));

       // Cf https://ethereum.github.io/yellowpaper/paper.pdf Appendix F
       if (v != 27 && v != 28) {
           return false;
       }

       // Cf https://ethereum.github.io/yellowpaper/paper.pdf Appendix F
       if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
           return false;
       }

       return _certificateSigners[ecrecover(tmp_hash, v, r, s)];
   }
}
