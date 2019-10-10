import { shouldFail } from 'openzeppelin-test-helpers';
const secp256k1 = require('secp256k1');

const TestCertificateController = artifacts.require('TestCertificateController');

const CERTIFICATE_SIGNER = '0x669026fd00d99ffdffc7c44968abbaf5777b1bf5';
const CERTIFICATE_SIGNER_PK = '0x91253726a4ff08860547613455e91d8b7cbcfd4afdfe1e2ee7f7ab0c1dede129';

const INVALID_CERTIFICATE = '0x00';

const getJsonForFunction = (
  _abi,
  _functionName
) => {
  for (let i = 0; i < _abi.length; i++) {
    if (_abi[i].name === _functionName) {
      return _abi[i];
    }
  }
  throw new Error('Function name not found in abi');
};

const getValidCertificate = async (
  _contract,
  _functionName,
  _address,
) => {
  let nonce = await _contract.checkCount(_address);
  let functionId = web3.eth.abi.encodeFunctionSignature(getJsonForFunction(_contract.abi, _functionName));
  // We need this prefix to verify messages in Solidity
  let msgHash = web3.utils.soliditySha3('\x19Ethereum Signed Message:\n32', functionId, nonce).replace(/0x/g, '');
  let msg = Buffer.from(msgHash, 'hex');
  let pk = Buffer.from(CERTIFICATE_SIGNER_PK.replace(/0x/g, ''), 'hex');
  let sig = secp256k1.sign(msg, pk);
  let recId = sig.recovery < 27 ? sig.recovery + 27 : sig.recovery;
  //                 v                    r     s
  return '0x' + recId.toString(16) + sig.signature.toString('hex');
};

contract('TestCertificateController', async accounts => {
  console.log(this);
  describe('The CertificateController contract', async function () {
    beforeEach(async function () {
      this.certificateSigner = accounts[1];
      this.randomUser = accounts[2];
      this.contract = await TestCertificateController.new(this.certificateSigner);
      this.contract.setCertificateSigner(CERTIFICATE_SIGNER, true, INVALID_CERTIFICATE, { from: this.certificateSigner });
    });
    describe('When a protected function is called', async function () {
      it('does not fail if the caller is a certificate signer', async function () {
        await this.contract.iNeedAValidCertificate(INVALID_CERTIFICATE, { from: this.certificateSigner });
      });
      it('does not fail if the caller is not a certificate signer but has a valid certificate', async function () {
        let cert = await getValidCertificate(this.contract, 'iNeedAValidCertificate', this.randomUser);
        await this.contract.iNeedAValidCertificate(cert, { from: this.randomUser });
      });
      it('does not fail if the caller is a certificate signer and has a valid certificate', async function () {
        let cert = await getValidCertificate(this.contract, 'iNeedAValidCertificate', this.certificateSigner);
        await this.contract.iNeedAValidCertificate(cert, { from: this.certificateSigner });
      });
      it('fails if the caller is not a certificate signer and does not have a valid certificate', async function () {
        await shouldFail.reverting(this.contract.iNeedAValidCertificate(INVALID_CERTIFICATE, { from: this.randomUser }));
      });
    });
  });
});
