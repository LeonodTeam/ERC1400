import { shouldFail } from 'openzeppelin-test-helpers';
const ethers = require('ethers');
const secp256k1 = require('secp256k1');

const MWTTOKEN = artifacts.require('MWT');

const CERTIFICATE_SIGNER = '0x669026fd00d99ffdffc7c44968abbaf5777b1bf5';
const CERTIFICATE_SIGNER_PK = '0x91253726a4ff08860547613455e91d8b7cbcfd4afdfe1e2ee7f7ab0c1dede129';

const partitionFlag = '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'; // Flag to indicate a partition change

const partition1Short = '7065725f30303030303000000000000000000000000000000000000000000000'; // per_000000 in hex
const partition2Short = '6d69645f30303030303000000000000000000000000000000000000000000000'; // mid_000000 in hex
const partition3Short = '6c6e675f30303030303000000000000000000000000000000000000000000000'; // lng_000000 in hex

const changeToPartition2 = partitionFlag.concat(partition2Short);
const partition1 = '0x'.concat(partition1Short);
const partition2 = '0x'.concat(partition2Short);
const partition3 = '0x'.concat(partition3Short);

const partitions = [partition1, partition2, partition3];
const reversedPartitions = [partition3, partition1, partition2];

const defaultPartitions = [partition1]; // per_000000

const issuanceAmount = 1000;

var balance;
var balanceByPartition;

const assertBalancesByPartition = async (
  _contract,
  _tokenHolder,
  _partitions,
  _amounts
) => {
  for (let i = 0; i < _partitions.length; i++) {
    await assertBalanceOfByPartition(_contract, _tokenHolder, _partitions[i], _amounts[i]);
  }
};

const assertBalanceOfByPartition = async (
  _contract,
  _tokenHolder,
  _partition,
  _amount
) => {
  balanceByPartition = await _contract.balanceOfByPartition(_partition, _tokenHolder);
  assert.equal(balanceByPartition, _amount);
};

const assertBalanceOf = async (
  _contract,
  _tokenHolder,
  _amount
) => {
  balance = await _contract.balanceOf(_tokenHolder);
  assert.equal(balance, _amount);
};

const issueOnMultiplePartitions = async (
  _contract,
  _owner,
  _recipient,
  _partitions,
  _amounts
) => {
  for (let i = 0; i < _partitions.length; i++) {
    let cert = await getValidCertificate(_contract, 'issueByPartition', _owner);
    await _contract.issueByPartition(_partitions[i], _recipient, _amounts[i], cert, { from: _owner });
  }
};

const getValidCertificate = async (
  _contract,
  _functionName,
  _address
) => {
  const contract = new ethers.Contract(_contract.address, _contract.abi, new ethers.providers.JsonRpcProvider());
  const nonce = (await _contract.checkCount(_address)).toString(16);
  const functionSig = await contract.interface.functions[_functionName].signature;
  const functionId = await ethers.utils.id(functionSig).slice(0, 10);
  // We need a bytes32, and the below function has strict parameter requirements
  const nonceAsBytes32 = '0x' + nonce.padStart(64 - nonce.length, '0');
  // Solidity exotically pads data depending on type... https://solidity.readthedocs.io/en/develop/abi-spec.html#non-standard-packed-mode
  const msgHash = ethers.utils.solidityKeccak256([ 'string', 'bytes4', 'bytes32' ], [ '\x19Ethereum Signed Message:\n32', functionId, nonceAsBytes32 ]);
  const msg = Buffer.from(msgHash.replace(/0x/g, ''), 'hex');
  const pk = Buffer.from(CERTIFICATE_SIGNER_PK.replace(/0x/g, ''), 'hex');
  const sig = secp256k1.sign(msg, pk);
  const recId = sig.recovery < 27 ? sig.recovery + 27 : sig.recovery;
  return '0x' + recId.toString(16) + sig.signature.toString('hex');
};

contract('Token contract', function ([owner, operator, controller, controller_alternative1, controller_alternative2, tokenHolder, recipient, unknown]) {
  describe('parameters', function () {
    beforeEach(async function () {
      this.token = await MWTTOKEN.new('MontessoriToken', 'MWT', 1, [controller], CERTIFICATE_SIGNER, defaultPartitions);
    });
    describe('name', function () {
      it('returns the name of the token', async function () {
        const name = await this.token.name();

        assert.equal(name, 'MontessoriToken');
      });
    });

    describe('symbol', function () {
      it('returns the symbol of the token', async function () {
        const symbol = await this.token.symbol();

        assert.equal(symbol, 'MWT');
      });
    });
  });

  describe('defaultPartitions', function () {
    beforeEach(async function () {
      this.token = await MWTTOKEN.new('MontessoriToken', 'MWT', 1, [controller], CERTIFICATE_SIGNER, defaultPartitions);
      const newDefaultPartitions = await this.token.getDefaultPartitions();
      assert.equal(newDefaultPartitions.length, 1);
      assert.equal(newDefaultPartitions[0], partition1);
    });
    describe('when the sender is the contract owner', function () {
      it('sets the list of token default partitions', async function () {
        // changing default partition should NEVER occur in production since
        // we use the first partition as the perpetual one
        await this.token.setDefaultPartitions(reversedPartitions, { from: owner });
        const newDefaultPartitions = await this.token.getDefaultPartitions();
        assert.equal(newDefaultPartitions.length, 3);
        assert.equal(newDefaultPartitions[0], partition3);
        assert.equal(newDefaultPartitions[1], partition1);
        assert.equal(newDefaultPartitions[2], partition2);
      });
    });
  });

  describe('operatorTransferByPartition', function () {
    const transferAmount = 300;

    beforeEach(async function () {
      this.token = await MWTTOKEN.new('MontessoriToken', 'MWT', 1, [controller], CERTIFICATE_SIGNER, defaultPartitions);
      let cert = await getValidCertificate(this.token, 'issueByPartition', owner);
      await this.token.issueByPartition(partition1, tokenHolder, issuanceAmount, cert, { from: owner });
    });
    describe('when the sender is an operator for this partition', function () {
      describe('when the sender has enough balance for this partition', function () {
        describe('when partition changes', function () {
          it('transfers the requested amount', async function () {
            await assertBalanceOfByPartition(this.token, tokenHolder, partition1, issuanceAmount);
            await assertBalanceOfByPartition(this.token, recipient, partition2, 0);

            await this.token.authorizeOperatorByPartition(partition1, operator, { from: tokenHolder });
            let cert = await getValidCertificate(this.token, 'operatorTransferByPartition', operator);
            await this.token.operatorTransferByPartition(partition1, tokenHolder, recipient, transferAmount, changeToPartition2, cert, { from: operator });

            await assertBalanceOfByPartition(this.token, tokenHolder, partition1, issuanceAmount - transferAmount);
            await assertBalanceOfByPartition(this.token, recipient, partition2, transferAmount);
          });
          it('converts the requested amount', async function () {
            await assertBalanceOfByPartition(this.token, tokenHolder, partition1, issuanceAmount);
            await assertBalanceOfByPartition(this.token, tokenHolder, partition2, 0);

            await this.token.authorizeOperatorByPartition(partition1, operator, { from: tokenHolder });
            let cert = await getValidCertificate(this.token, 'operatorTransferByPartition', operator);
            await this.token.operatorTransferByPartition(partition1, tokenHolder, tokenHolder, transferAmount, changeToPartition2, cert, { from: operator });

            await assertBalanceOfByPartition(this.token, tokenHolder, partition1, issuanceAmount - transferAmount);
            await assertBalanceOfByPartition(this.token, tokenHolder, partition2, transferAmount);
          });
        });
      });
    });
  });
  describe('transfer', function () {
    beforeEach(async function () {
      this.token = await MWTTOKEN.new('MontessoriToken', 'MWT', 1, [controller], CERTIFICATE_SIGNER, defaultPartitions);
    });
    describe('when should behave as an ERC20', function () {
      it('transfer the requested amount', async function () {
        let cert = await getValidCertificate(this.token, 'issueByPartition', owner);
        await this.token.issueByPartition(partitions[0], tokenHolder, issuanceAmount, cert, { from: owner });

        const amountTransfered = 10;
        await this.token.transfer(recipient, amountTransfered, { from: tokenHolder });

        await assertBalanceOf(this.token, recipient, amountTransfered);
        await assertBalanceOf(this.token, tokenHolder, issuanceAmount - amountTransfered);

        // recipient should have perpetual partition listed
        const partitionsOfRecipient = await this.token.partitionsOf(recipient);
        assert.equal(partitionsOfRecipient.length, 1);
        assert.equal(partitionsOfRecipient[0], partitions[0]);

        // tokenHolder should still have perpetual partition listed
        const partitionsOfTokenHolder = await this.token.partitionsOf(tokenHolder);
        assert.equal(partitionsOfTokenHolder.length, 1);
        assert.equal(partitionsOfTokenHolder[0], partitions[0]);

        // check balance of perpetual partition
        await assertBalancesByPartition(this.token, recipient, [partitions[0]], [amountTransfered]);
      });
      it('should remove the token holder default partition when transfering all perpetual balance', async function () {
        let cert = await getValidCertificate(this.token, 'issueByPartition', owner);
        await this.token.issueByPartition(partitions[0], tokenHolder, issuanceAmount, cert, { from: owner });
        await this.token.transfer(recipient, issuanceAmount, { from: tokenHolder });

        await assertBalanceOf(this.token, recipient, issuanceAmount);
        await assertBalanceOf(this.token, tokenHolder, 0);

        // recipient should have perpetual partition listed
        const partitionsOfRecipient = await this.token.partitionsOf(recipient);
        assert.equal(partitionsOfRecipient.length, 1);
        assert.equal(partitionsOfRecipient[0], partitions[0]);

        // tokenHolder should not have perpetual partition listed
        const partitionsOfTokenHolder = await this.token.partitionsOf(tokenHolder);
        assert.equal(partitionsOfTokenHolder.length, 0);

        // check balance of perpetual partition
        await assertBalancesByPartition(this.token, recipient, [partitions[0]], [issuanceAmount]);
        await assertBalancesByPartition(this.token, tokenHolder, [partitions[0]], [0]);
      });
      it('emits a Transfer event', async function () {
        let cert = await getValidCertificate(this.token, 'issueByPartition', owner);
        await this.token.issueByPartition(partitions[0], tokenHolder, issuanceAmount, cert, { from: owner });
        const { logs } = await this.token.transfer(recipient, issuanceAmount, { from: tokenHolder });

        assert.equal(logs.length, 2);
        assert.equal(logs[0].event, 'TransferWithData');
        assert.equal(logs[0].args.operator, tokenHolder);
        assert.equal(logs[0].args.from, tokenHolder);
        assert.equal(logs[0].args.to, recipient);
        assert.equal(logs[0].args.value, issuanceAmount);
        assert.equal(logs[0].args.data, null);
        assert.equal(logs[0].args.operatorData, null);

        assert.equal(logs[1].event, 'Transfer');
        assert.equal(logs[1].args.from, tokenHolder);
        assert.equal(logs[1].args.to, recipient);
        assert.equal(logs[1].args.value, issuanceAmount);
      });
      it('sould fail if sender does not have sufficient perpetual balance', async function () {
        await issueOnMultiplePartitions(this.token, owner, tokenHolder, partitions, [issuanceAmount, issuanceAmount, issuanceAmount]);

        await shouldFail.reverting(this.token.transfer(recipient, issuanceAmount + 10, { from: tokenHolder }));

        await assertBalancesByPartition(this.token, tokenHolder, partitions, [issuanceAmount, issuanceAmount, issuanceAmount]);
        await assertBalancesByPartition(this.token, recipient, partitions, [0, 0, 0]);
      });
    });
    it('balanceOf method should only return perpetual (default) partition balance', async function () {
      let cert = await getValidCertificate(this.token, 'issueByPartition', owner);
      await this.token.issueByPartition(partitions[0], tokenHolder, issuanceAmount, cert, { from: owner });
      cert = await getValidCertificate(this.token, 'issueByPartition', owner);
      await this.token.issueByPartition(partitions[1], tokenHolder, issuanceAmount, cert, { from: owner });
      cert = await getValidCertificate(this.token, 'issueByPartition', owner);
      await this.token.issueByPartition(partitions[2], tokenHolder, issuanceAmount, cert, { from: owner });

      const senderBalance = await this.token.balanceOf(tokenHolder);
      assert.equal(senderBalance, issuanceAmount);
    });
    it('needWhitelist tests', async function () {
      const bool = await this.token.needWhitelist();
      assert.equal(bool, false);

      await this.token.setNeedWhitelisting(true, { from: owner });
      const bool2 = await this.token.needWhitelist();
      assert.equal(bool2, true);

      await this.token.setNeedWhitelisting(false, { from: owner });
      const bool3 = await this.token.needWhitelist();
      assert.equal(bool3, false);
    });
    describe('when whitelist is required for an ERC20 transfer', function () {
      it('should success if both participants are whitelised', async function () {
        let cert = await getValidCertificate(this.token, 'issueByPartition', owner);
        await this.token.issueByPartition(partitions[0], tokenHolder, issuanceAmount, cert, { from: owner });

        await this.token.setNeedWhitelisting(true, { from: owner });

        await this.token.setWhitelisted(tokenHolder, true, { from: controller });
        assert(await this.token.whitelisted(tokenHolder));

        await this.token.setWhitelisted(recipient, true, { from: controller });
        assert(await this.token.whitelisted(recipient));

        const amountTransfered = 10;
        await this.token.transfer(recipient, amountTransfered, { from: tokenHolder });
        const senderBalance = await this.token.balanceOf(tokenHolder);
        assert.equal(senderBalance, issuanceAmount - amountTransfered);
      });
      it('should fail if one of the participant is not whitelisted', async function () {
        let cert = await getValidCertificate(this.token, 'issueByPartition', owner);
        await this.token.issueByPartition(partitions[0], tokenHolder, issuanceAmount, cert, { from: owner });

        await this.token.setNeedWhitelisting(true, { from: owner });

        const amountTransfered = 10;
        await shouldFail.reverting(this.token.transfer(recipient, amountTransfered, { from: tokenHolder }));
      });
      it('should pass if one of the participant is not whitelisted but white listing not neeed', async function () {
        let cert = await getValidCertificate(this.token, 'issueByPartition', owner);
        await this.token.issueByPartition(partitions[0], tokenHolder, issuanceAmount, cert, { from: owner });

        await this.token.setNeedWhitelisting(false, { from: owner });

        const amountTransfered = 10;
        await this.token.transfer(recipient, amountTransfered, { from: tokenHolder });
        const senderBalance = await this.token.balanceOf(tokenHolder);
        assert.equal(senderBalance, issuanceAmount - amountTransfered);
      });
    });
  });
  describe('Minter removal', function () {
    beforeEach(async function () {
      this.token = await MWTTOKEN.new('MontessoriToken', 'MWT', 1, [controller], CERTIFICATE_SIGNER, defaultPartitions);
    });
    describe('tests add/remove minter', function () {
      it('add remove minter', async function () {
        // unknown address is not minter by default
        const isMinter = await this.token.isMinter(unknown);
        assert.equal(isMinter, false);

        await this.token.addMinter(unknown, { from: owner });
        const isMinter2 = await this.token.isMinter(unknown);
        assert.equal(isMinter2, true);

        await this.token.removeMinter(unknown, { from: owner });
        const isMinter3 = await this.token.isMinter(unknown);
        assert.equal(isMinter3, false);
      });
      it('add remove minter fail if made by OnlyMinter', async function () {
        // unknown address is not minter by default
        const isMinter = await this.token.isMinter(unknown);
        assert.equal(isMinter, false);

        await this.token.addMinter(unknown, { from: owner });
        const isMinter2 = await this.token.isMinter(unknown);
        assert.equal(isMinter2, true);

        // unknown is now minter, let's check if he can add a minter
        // since we updated method addMinter to be onlyMinter, this should fail
        const isMinter4 = await this.token.isMinter(recipient);
        assert.equal(isMinter4, false);
        await shouldFail.reverting(this.token.addMinter(recipient, { from: unknown }));
        const isMinter5 = await this.token.isMinter(recipient);
        assert.equal(isMinter5, false);
      });
      it('if owner/minter removes himself', async function () {
        // owner address is minter by default
        const isMinter = await this.token.isMinter(owner);
        assert.equal(isMinter, true);

        // owner is not minter anymore
        await this.token.removeMinter(owner, { from: owner });
        const isMinter2 = await this.token.isMinter(owner);
        assert.equal(isMinter2, false);

        // but he can add himself as minter again
        await this.token.addMinter(owner, { from: owner });
        const isMinter3 = await this.token.isMinter(owner);
        assert.equal(isMinter3, true);
      });
      it('if minter removes himself', async function () {
        // unknown address is not minter by default
        const isMinter = await this.token.isMinter(unknown);
        assert.equal(isMinter, false);

        await this.token.addMinter(unknown, { from: owner });
        const isMinter2 = await this.token.isMinter(unknown);
        assert.equal(isMinter2, true);

        // he can not add another minter
        const isMinter3 = await this.token.isMinter(recipient);
        assert.equal(isMinter3, false);
        await shouldFail.reverting(this.token.addMinter(recipient, { from: unknown }));
        const isMinter4 = await this.token.isMinter(recipient);
        assert.equal(isMinter4, false);

        // unknown is not minter anymore
        await this.token.renounceMinter({ from: unknown });
        const isMinter5 = await this.token.isMinter(unknown);
        assert.equal(isMinter5, false);

        // but he cannot add himself as minter again
        await shouldFail.reverting(this.token.addMinter(unknown, { from: unknown }));
        const isMinter6 = await this.token.isMinter(unknown);
        assert.equal(isMinter6, false);
      });
    });
    describe('if the owner removes the right to mint tokens', function () {
      it('The former minter cannot mint anymore', async function () {
        let issuanceAmount = 1000;
        let cert = await getValidCertificate(this.token, 'issueByPartition', tokenHolder);
        await this.token.addMinter(tokenHolder, { from: owner });

        await this.token.issueByPartition(partitions[0], tokenHolder, issuanceAmount, cert, { from: tokenHolder });
        await assertBalanceOf(this.token, tokenHolder, issuanceAmount);

        await this.token.removeMinter(tokenHolder, { from: owner });
        const isMinter = await this.token.isMinter(tokenHolder);
        assert.equal(isMinter, false);
        await shouldFail.reverting(this.token.issueByPartition(partitions[0], tokenHolder, issuanceAmount, cert, { from: tokenHolder }));

        // The balance is still the same as the initial issued balance
        await assertBalanceOf(this.token, tokenHolder, issuanceAmount);
      });
    });
  });
  describe('Certificate tests', function () {
    beforeEach(async function () {
      this.token = await MWTTOKEN.new('MontessoriToken', 'MWT', 1, [controller], CERTIFICATE_SIGNER, defaultPartitions);
      let cert = await getValidCertificate(this.token, 'issueByPartition', owner);
      await this.token.issueByPartition(partition1, tokenHolder, issuanceAmount, cert, { from: owner });
    });
    describe('when a certificate is used', function () {
      it('partition change should success if certificate is used well', async function () {
        const transferAmount = 300;
        await this.token.authorizeOperatorByPartition(partition1, unknown, { from: tokenHolder });
        let cert = await getValidCertificate(this.token, 'operatorTransferByPartition', unknown);
        await this.token.operatorTransferByPartition(partition1, tokenHolder, recipient, transferAmount, changeToPartition2, cert, { from: unknown });

        await assertBalanceOfByPartition(this.token, tokenHolder, partition1, issuanceAmount - transferAmount);
        await assertBalanceOfByPartition(this.token, recipient, partition2, transferAmount);
      });
      it('partition change should fail if certificate is used badly', async function () {
        const transferAmount = 300;
        await this.token.authorizeOperatorByPartition(partition1, unknown, { from: tokenHolder });
        let cert = await getValidCertificate(this.token, 'transferByPartition', unknown);
        await shouldFail.reverting(this.token.operatorTransferByPartition(partition1, tokenHolder, recipient, transferAmount, changeToPartition2, cert, { from: unknown }));

        await assertBalanceOfByPartition(this.token, tokenHolder, partition1, issuanceAmount);
        await assertBalanceOfByPartition(this.token, recipient, partition2, 0);
      });
    });
  });
});
