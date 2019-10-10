pragma solidity ^0.5.3;

import "../CertificateController/CertificateController.sol";

contract TestCertificateController is CertificateController {

    constructor (
        address certificateSigner
    ) public
    CertificateController(certificateSigner)
    {
    }

    function setCertificateSigner (
      address certificateSigner,
      bool authorized,
      bytes memory cert
    )
    public isValidCertificate(cert)
    {
      _setCertificateSigner(certificateSigner, authorized);
    }

    function iNeedAValidCertificate (bytes memory cert) public isValidCertificate(cert) returns (bool) {
        return true;
    }
}
