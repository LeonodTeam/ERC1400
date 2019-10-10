import { shouldFail } from 'openzeppelin-test-helpers';
const ethers = require('ethers');
const secp256k1 = require('secp256k1');

const ERC1400Raw = artifacts.require('ERC1400RawMock');
const ERC1820Registry = artifacts.require('ERC1820Registry');
const ERC1400TokensSender = artifacts.require('ERC1400TokensSenderMock');
const ERC1400TokensRecipient = artifacts.require('ERC1400TokensRecipientMock');

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';
const ZERO_BYTE = '0x';

const CERTIFICATE_SIGNER = '0x669026fd00d99ffdffc7c44968abbaf5777b1bf5';
const CERTIFICATE_SIGNER_PK = '0x91253726a4ff08860547613455e91d8b7cbcfd4afdfe1e2ee7f7ab0c1dede129';

const INVALID_CERTIFICATE_SENDER = '0x1100000000000000000000000000000000000000000000000000000000000000';
const INVALID_CERTIFICATE_RECIPIENT = '0x2200000000000000000000000000000000000000000000000000000000000000';

const initialSupply = 1000000000;

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

contract('ERC1400Raw without hooks', function ([owner, operator, controller, controller_alternative1, controller_alternative2, tokenHolder, recipient, unknown]) {
  // ADDITIONNAL MOCK TESTS

  describe('Additionnal mock tests', function () {
    beforeEach(async function () {
      this.token = await ERC1400Raw.new('ERC1400RawToken', 'DAU', 1, [controller], CERTIFICATE_SIGNER);
    });

    describe('contract creation', function () {
      it('fails deploying the contract if granularity is lower than 1', async function () {
        await shouldFail.reverting(ERC1400Raw.new('ERC1400RawToken', 'DAU', 0, [controller], CERTIFICATE_SIGNER));
      });
    });

    describe('_isRegularAddress', function () {
      it('returns true when address is correct', async function () {
        assert.isTrue(await this.token.isRegularAddress(owner));
      });
      it('returns true when address is non zero', async function () {
        assert.isTrue(await this.token.isRegularAddress(owner));
      });
      it('returns false when address is ZERO_ADDRESS', async function () {
        assert.isTrue(!(await this.token.isRegularAddress(ZERO_ADDRESS)));
      });
    });
  });

  // BASIC FUNCTIONNALITIES

  describe('parameters', function () {
    beforeEach(async function () {
      this.token = await ERC1400Raw.new('ERC1400RawToken', 'DAU', 1, [controller], CERTIFICATE_SIGNER);
    });

    describe('name', function () {
      it('returns the name of the token', async function () {
        const name = await this.token.name();

        assert.equal(name, 'ERC1400RawToken');
      });
    });

    describe('symbol', function () {
      it('returns the symbol of the token', async function () {
        const symbol = await this.token.symbol();

        assert.equal(symbol, 'DAU');
      });
    });

    describe('total supply', function () {
      it('returns the total amount of tokens', async function () {
        let cert = await getValidCertificate(this.token, 'issue', owner);
        await this.token.issue(tokenHolder, initialSupply, cert, { from: owner });
        const totalSupply = await this.token.totalSupply();

        assert.equal(totalSupply, initialSupply);
      });
    });

    describe('balanceOf', function () {
      describe('when the requested account has no tokens', function () {
        it('returns zero', async function () {
          const balance = await this.token.balanceOf(unknown);

          assert.equal(balance, 0);
        });
      });

      describe('when the requested account has some tokens', function () {
        it('returns the total amount of tokens', async function () {
          let cert = await getValidCertificate(this.token, 'issue', owner);
          await this.token.issue(tokenHolder, initialSupply, cert, { from: owner });
          const balance = await this.token.balanceOf(tokenHolder);

          assert.equal(balance, initialSupply);
        });
      });
    });

    describe('granularity', function () {
      it('returns the granularity of tokens', async function () {
        const granularity = await this.token.granularity();

        assert.equal(granularity, 1);
      });
    });

    describe('controllers', function () {
      it('returns the list of controllers', async function () {
        const controllers = await this.token.controllers();

        assert.equal(controllers.length, 1);
        assert.equal(controllers[0], controller);
      });
    });

    describe('authorizeOperator', function () {
      describe('when sender authorizes an operator', function () {
        it('authorizes the operator', async function () {
          assert.isTrue(!(await this.token.isOperator(operator, tokenHolder)));
          await this.token.authorizeOperator(operator, { from: tokenHolder });
          assert.isTrue(await this.token.isOperator(operator, tokenHolder));
        });
        it('emits a authorized event', async function () {
          const { logs } = await this.token.authorizeOperator(operator, { from: tokenHolder });

          assert.equal(logs.length, 1);
          assert.equal(logs[0].event, 'AuthorizedOperator');
          assert.equal(logs[0].args.operator, operator);
          assert.equal(logs[0].args.tokenHolder, tokenHolder);
        });
      });
      describe('when sender authorizes himself', function () {
        it('reverts', async function () {
          await shouldFail.reverting(this.token.authorizeOperator(tokenHolder, { from: tokenHolder }));
        });
      });
    });

    describe('revokeOperator', function () {
      describe('when sender revokes an operator', function () {
        it('revokes the operator (when operator is not the controller)', async function () {
          assert.isTrue(!(await this.token.isOperator(operator, tokenHolder)));
          await this.token.authorizeOperator(operator, { from: tokenHolder });
          assert.isTrue(await this.token.isOperator(operator, tokenHolder));

          await this.token.revokeOperator(operator, { from: tokenHolder });

          assert.isTrue(!(await this.token.isOperator(operator, tokenHolder)));
        });
        it('emits a revoked event', async function () {
          const { logs } = await this.token.revokeOperator(controller, { from: tokenHolder });

          assert.equal(logs.length, 1);
          assert.equal(logs[0].event, 'RevokedOperator');
          assert.equal(logs[0].args.operator, controller);
          assert.equal(logs[0].args.tokenHolder, tokenHolder);
        });
      });
      describe('when sender revokes himself', function () {
        it('reverts', async function () {
          await shouldFail.reverting(this.token.revokeOperator(tokenHolder, { from: tokenHolder }));
        });
      });
    });

    describe('isOperator', function () {
      it('when operator is tokenHolder', async function () {
        assert.isTrue(await this.token.isOperator(tokenHolder, tokenHolder));
      });
      it('when operator is authorized by tokenHolder', async function () {
        await this.token.authorizeOperator(operator, { from: tokenHolder });
        assert.isTrue(await this.token.isOperator(operator, tokenHolder));
      });
      it('when is a revoked operator', async function () {
        await this.token.revokeOperator(controller, { from: tokenHolder });
        assert.isTrue(!(await this.token.isOperator(controller, tokenHolder)));
      });
    });

    // SET CONTROLLERS

    describe('setControllers', function () {
      describe('when the caller is the contract owner', function () {
        it('sets the operators as controllers', async function () {
          const controllers1 = await this.token.controllers();
          assert.equal(controllers1.length, 1);
          assert.equal(controllers1[0], controller);
          assert.isTrue(!(await this.token.isOperator(controller, unknown)));
          assert.isTrue(!(await this.token.isOperator(controller_alternative1, unknown)));
          assert.isTrue(!(await this.token.isOperator(controller_alternative2, unknown)));
          await this.token.setControllable(true, { from: owner });
          assert.isTrue(await this.token.isOperator(controller, unknown));
          assert.isTrue(!(await this.token.isOperator(controller_alternative1, unknown)));
          assert.isTrue(!(await this.token.isOperator(controller_alternative2, unknown)));
          await this.token.setControllers([controller_alternative1, controller_alternative2], { from: owner });
          const controllers2 = await this.token.controllers();
          assert.equal(controllers2.length, 2);
          assert.equal(controllers2[0], controller_alternative1);
          assert.equal(controllers2[1], controller_alternative2);
          assert.isTrue(!(await this.token.isOperator(controller, unknown)));
          assert.isTrue(await this.token.isOperator(controller_alternative1, unknown));
          assert.isTrue(await this.token.isOperator(controller_alternative2, unknown));
          await this.token.setControllable(false, { from: owner });
          assert.isTrue(!(await this.token.isOperator(controller_alternative1, unknown)));
          assert.isTrue(!(await this.token.isOperator(controller_alternative1, unknown)));
          assert.isTrue(!(await this.token.isOperator(controller_alternative2, unknown)));
        });
      });
      describe('when the caller is not the contract owner', function () {
        it('reverts', async function () {
          await shouldFail.reverting(this.token.setControllers([controller_alternative1, controller_alternative2], { from: unknown }));
        });
      });
    });

    // ISSUE

    describe('issue', function () {
      describe('when the caller is a issuer', function () {
        describe('when the amount is a multiple of the granularity', function () {
          describe('when the recipient is not the zero address', function () {
            it('issues the requested amount', async function () {
              let cert = await getValidCertificate(this.token, 'issue', owner);
              await this.token.issue(tokenHolder, initialSupply, cert, { from: owner });

              const totalSupply = await this.token.totalSupply();
              const balance = await this.token.balanceOf(tokenHolder);

              assert.equal(totalSupply, initialSupply);
              assert.equal(balance, initialSupply);
            });
            it('emits a sent event', async function () {
              let cert = await getValidCertificate(this.token, 'issue', owner);
              const { logs } = await this.token.issue(tokenHolder, initialSupply, cert, { from: owner });

              assert.equal(logs.length, 2);

              assert.equal(logs[0].event, 'Checked');
              assert.equal(logs[0].args.sender, owner);

              assert.equal(logs[1].event, 'Issued');
              assert.equal(logs[1].args.operator, owner);
              assert.equal(logs[1].args.to, tokenHolder);
              assert.equal(logs[1].args.value, initialSupply);
              assert.equal(logs[1].args.data, cert);
              assert.equal(logs[1].args.operatorData, null);
            });
          });
          describe('when the recipient is the zero address', function () {
            it('reverts', async function () {
              let cert = await getValidCertificate(this.token, 'issue', owner);
              await shouldFail.reverting(this.token.issue(ZERO_ADDRESS, initialSupply, cert, { from: owner }));
            });
          });
        });
        describe('when the amount is not a multiple of the granularity', function () {
          it('reverts', async function () {
            this.token = await ERC1400Raw.new('ERC1400RawToken', 'DAU', 2, [], CERTIFICATE_SIGNER);
            let cert = await getValidCertificate(this.token, 'issue', owner);
            await shouldFail.reverting(this.token.issue(tokenHolder, 3, cert, { from: owner }));
          });
        });
      });
      describe('when the caller is not a issuer', function () {
        it('reverts', async function () {
          let cert = await getValidCertificate(this.token, 'issue', owner);
          await shouldFail.reverting(this.token.issue(tokenHolder, initialSupply, cert, { from: unknown }));
        });
      });
    });

    // TRANSFERWITHDATA

    describe('transferWithData', function () {
      const to = recipient;
      beforeEach(async function () {
        let cert = await getValidCertificate(this.token, 'issue', owner);
        await this.token.issue(tokenHolder, initialSupply, cert, { from: owner });
      });
      describe('when the amount is a multiple of the granularity', function () {
        describe('when the recipient is not the zero address', function () {
          describe('when the sender has enough balance', function () {
            const amount = initialSupply;
            describe('when the recipient is a regular address', function () {
              it('transfers the requested amount', async function () {
                let cert = await getValidCertificate(this.token, 'transferWithData', tokenHolder);
                await this.token.transferWithData(to, amount, cert, { from: tokenHolder });
                const senderBalance = await this.token.balanceOf(tokenHolder);
                assert.equal(senderBalance, initialSupply - amount);

                const recipientBalance = await this.token.balanceOf(to);
                assert.equal(recipientBalance, amount);
              });

              it('emits a sent event', async function () {
                let cert = await getValidCertificate(this.token, 'transferWithData', tokenHolder);
                const { logs } = await this.token.transferWithData(to, amount, cert, { from: tokenHolder });

                assert.equal(logs.length, 2);

                assert.equal(logs[0].event, 'Checked');
                assert.equal(logs[0].args.sender, tokenHolder);

                assert.equal(logs[1].event, 'TransferWithData');
                assert.equal(logs[1].args.operator, tokenHolder);
                assert.equal(logs[1].args.from, tokenHolder);
                assert.equal(logs[1].args.to, to);
                assert.equal(logs[1].args.value, amount);
                assert.equal(logs[1].args.data, cert);
                assert.equal(logs[1].args.operatorData, null);
              });
            });
            describe('when the recipient is not a regular address', function () {
              it('reverts', async function () {
                let cert = await getValidCertificate(this.token, 'transferWithData', tokenHolder);
                await shouldFail.reverting(this.token.transferWithData(this.token.address, amount, cert, { from: tokenHolder }));
              });
            });
          });
          describe('when the sender does not have enough balance', function () {
            const amount = initialSupply + 1;

            it('reverts', async function () {
              let cert = await getValidCertificate(this.token, 'transferWithData', tokenHolder);
              await shouldFail.reverting(this.token.transferWithData(to, amount, cert, { from: tokenHolder }));
            });
          });
        });

        describe('when the recipient is the zero address', function () {
          const amount = initialSupply;
          const to = ZERO_ADDRESS;

          it('reverts', async function () {
            let cert = await getValidCertificate(this.token, 'transferWithData', tokenHolder);
            await shouldFail.reverting(this.token.transferWithData(to, amount, cert, { from: tokenHolder }));
          });
        });
      });
      describe('when the amount is not a multiple of the granularity', function () {
        it('reverts', async function () {
          this.token = await ERC1400Raw.new('ERC1400RawToken', 'DAU', 2, [], CERTIFICATE_SIGNER);
          let cert = await getValidCertificate(this.token, 'issue', owner);
          await this.token.issue(tokenHolder, initialSupply, cert, { from: owner });
          cert = await getValidCertificate(this.token, 'transferWithData', tokenHolder);
          await shouldFail.reverting(this.token.transferWithData(to, 3, cert, { from: tokenHolder }));
        });
      });
    });

    // TRANSFERFROMWITHDATA

    describe('transferFromWithData', function () {
      const to = recipient;
      beforeEach(async function () {
        let cert = await getValidCertificate(this.token, 'issue', owner);
        await this.token.issue(tokenHolder, initialSupply, cert, { from: owner });
      });
      describe('when the operator is approved', function () {
        beforeEach(async function () {
          await this.token.authorizeOperator(operator, { from: tokenHolder });
        });
        describe('when the amount is a multiple of the granularity', function () {
          describe('when the recipient is not the zero address', function () {
            
            describe('when the sender has enough balance', function () {
              const amount = initialSupply;

              it('transfers the requested amount', async function () {
                let cert = await getValidCertificate(this.token, 'transferFromWithData', operator);
                await this.token.transferFromWithData(tokenHolder, to, amount, ZERO_BYTE, cert, { from: operator });
                const senderBalance = await this.token.balanceOf(tokenHolder);
                assert.equal(senderBalance, initialSupply - amount);

                const recipientBalance = await this.token.balanceOf(to);
                assert.equal(recipientBalance, amount);
              });

              it('emits a sent event [with ERC20 retrocompatibility]', async function () {
                let cert = await getValidCertificate(this.token, 'transferFromWithData', operator);
                const { logs } = await this.token.transferFromWithData(tokenHolder, to, amount, ZERO_BYTE, cert, { from: operator });

                assert.equal(logs.length, 2);

                assert.equal(logs[0].event, 'Checked');
                assert.equal(logs[0].args.sender, operator);

                assert.equal(logs[1].event, 'TransferWithData');
                assert.equal(logs[1].args.operator, operator);
                assert.equal(logs[1].args.from, tokenHolder);
                assert.equal(logs[1].args.to, to);
                assert.equal(logs[1].args.value, amount);
                assert.equal(logs[1].args.data, null);
                assert.equal(logs[1].args.operatorData, cert);
              });
            });
            describe('when the sender does not have enough balance', function () {
              const amount = initialSupply + 1;

              it('reverts', async function () {
                let cert = await getValidCertificate(this.token, 'transferFromWithData', operator);
                await shouldFail.reverting(this.token.transferFromWithData(tokenHolder, to, amount, ZERO_BYTE, cert, { from: operator }));
              });
            });
          });

          describe('when the recipient is the zero address', function () {
            const amount = initialSupply;
            const to = ZERO_ADDRESS;

            it('reverts', async function () {
              let cert = await getValidCertificate(this.token, 'transferFromWithData', operator);
              await shouldFail.reverting(this.token.transferFromWithData(tokenHolder, to, amount, ZERO_BYTE, cert, { from: operator }));
            });
          });
        });
        describe('when the amount is not a multiple of the granularity', function () {
          it('reverts', async function () {
            this.token = await ERC1400Raw.new('ERC1400RawToken', 'DAU', 2, [], CERTIFICATE_SIGNER);
            let cert = await getValidCertificate(this.token, 'issue', owner);
            await this.token.issue(tokenHolder, initialSupply, cert, { from: owner });
            cert = await getValidCertificate(this.token, 'transferFromWithData', operator);
            await shouldFail.reverting(this.token.transferFromWithData(tokenHolder, to, 3, ZERO_BYTE, cert, { from: operator }));
          });
        });
      });
      describe('when the operator is not approved', function () {
        it('reverts', async function () {
          const amount = initialSupply;
          let cert = await getValidCertificate(this.token, 'transferFromWithData', operator);
          await shouldFail.reverting(this.token.transferFromWithData(tokenHolder, to, amount, ZERO_BYTE, cert, { from: operator }));
        });
      });
    });

    // REDEEM

    describe('redeem', function () {
      beforeEach(async function () {
        let cert = await getValidCertificate(this.token, 'issue', owner);
        await this.token.issue(tokenHolder, initialSupply, cert, { from: owner });
      });

      describe('when the amount is a multiple of the granularity', function () {
        describe('when the redeemer has enough balance', function () {
          const amount = initialSupply;

          it('redeems the requested amount', async function () {
            let cert = await getValidCertificate(this.token, 'redeem', tokenHolder);
            await this.token.redeem(amount, cert, { from: tokenHolder });
            const senderBalance = await this.token.balanceOf(tokenHolder);
            assert.equal(senderBalance, initialSupply - amount);
          });

          it('emits a redeemed event [with ERC20 retrocompatibility]', async function () {
            let cert = await getValidCertificate(this.token, 'redeem', tokenHolder);
            const { logs } = await this.token.redeem(amount, cert, { from: tokenHolder });

            assert.equal(logs.length, 2);

            assert.equal(logs[0].event, 'Checked');
            assert.equal(logs[0].args.sender, tokenHolder);

            assert.equal(logs[1].event, 'Redeemed');
            assert.equal(logs[1].args.operator, tokenHolder);
            assert.equal(logs[1].args.from, tokenHolder);
            assert.equal(logs[1].args.value, amount);
            assert.equal(logs[1].args.data, cert);
            assert.equal(logs[1].args.operatorData, null);
          });
        });
        describe('when the redeemer does not have enough balance', function () {
          const amount = initialSupply + 1;

          it('reverts', async function () {
            let cert = await getValidCertificate(this.token, 'redeem', tokenHolder);
            await shouldFail.reverting(this.token.redeem(amount, cert, { from: tokenHolder }));
          });
        });
      });
      describe('when the amount is not a multiple of the granularity', function () {
        it('reverts', async function () {
          this.token = await ERC1400Raw.new('ERC1400RawToken', 'DAU', 2, [], CERTIFICATE_SIGNER);
          let cert = await getValidCertificate(this.token, 'issue', owner);
          await this.token.issue(tokenHolder, initialSupply, cert, { from: owner });
          cert = await getValidCertificate(this.token, 'redeem', tokenHolder);
          await shouldFail.reverting(this.token.redeem(3, cert, { from: tokenHolder }));
        });
      });
    });

    // REDEEMFROM

    describe('redeemFrom', function () {
      beforeEach(async function () {
        let cert = await getValidCertificate(this.token, 'issue', tokenHolder);
        await this.token.issue(tokenHolder, initialSupply, cert, { from: owner });
      });

      beforeEach(async function () {
        await this.token.authorizeOperator(operator, { from: tokenHolder });
      });
      describe('when the amount is a multiple of the granularity', function () {
        describe('when the redeemer is not the zero address', function () {
          describe('when the redeemer does not have enough balance', function () {
            const amount = initialSupply + 1;

            it('reverts', async function () {
              let cert = await getValidCertificate(this.token, 'redeemFrom', operator);
              await shouldFail.reverting(this.token.redeemFrom(tokenHolder, amount, ZERO_BYTE, cert, { from: operator }));
            });
          });

          describe('when the redeemer has enough balance', function () {
            const amount = initialSupply;

            it('redeems the requested amount', async function () {
              let cert = await getValidCertificate(this.token, 'redeemFrom', operator);
              await this.token.redeemFrom(tokenHolder, amount, ZERO_BYTE, cert, { from: operator });
              const senderBalance = await this.token.balanceOf(tokenHolder);
              assert.equal(senderBalance, initialSupply - amount);
            });

            it('emits a redeemed event [with ERC20 retrocompatibility]', async function () {
              let cert = await getValidCertificate(this.token, 'redeemFrom', operator);
              const { logs } = await this.token.redeemFrom(tokenHolder, amount, ZERO_BYTE, cert, { from: operator });

              assert.equal(logs.length, 2);

              assert.equal(logs[0].event, 'Checked');
              assert.equal(logs[0].args.sender, operator);

              assert.equal(logs[1].event, 'Redeemed');
              assert.equal(logs[1].args.operator, operator);
              assert.equal(logs[1].args.from, tokenHolder);
              assert.equal(logs[1].args.value, amount);
              assert.equal(logs[1].args.data, null);
              assert.equal(logs[1].args.operatorData, cert);
            });
          });
        });

        describe('when the redeemer is the zero address', function () {
          it('reverts', async function () {
            const amount = initialSupply;
            await shouldFail.reverting(this.token.redeemFromMock(ZERO_ADDRESS, amount, ZERO_BYTE, ZERO_BYTE, { from: operator }));
          });
        });
      });
      describe('when the amount is not a multiple of the granularity', function () {
        it('reverts', async function () {
          this.token = await ERC1400Raw.new('ERC1400RawToken', 'DAU', 2, [], CERTIFICATE_SIGNER);
          let cert = await getValidCertificate(this.token, 'issue', owner);
          await this.token.issue(tokenHolder, initialSupply, cert, { from: owner });
          cert = await getValidCertificate(this.token, 'redeemFrom', operator);
          await shouldFail.reverting(this.token.redeemFrom(tokenHolder, 3, ZERO_BYTE, cert, { from: operator }));
        });
      });
    });
  });
});

contract('ERC1400Raw with hooks', function ([owner, operator, controller, tokenHolder, recipient, unknown]) {
  // HOOKS

  describe('hooks', function () {
    const amount = initialSupply;
    const to = recipient;

    beforeEach(async function () {
      this.token = await ERC1400Raw.new('ERC1400RawToken', 'DAU', 1, [controller], CERTIFICATE_SIGNER);
      this.registry = await ERC1820Registry.at('0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24');

      this.senderContract = await ERC1400TokensSender.new('ERC1400TokensSender', { from: tokenHolder });
      await this.registry.setManager(tokenHolder, this.senderContract.address, { from: tokenHolder });
      await this.senderContract.setERC1820Implementer({ from: tokenHolder });

      this.recipientContract = await ERC1400TokensRecipient.new('ERC1400TokensRecipient', { from: recipient });
      await this.registry.setManager(recipient, this.recipientContract.address, { from: recipient });
      await this.recipientContract.setERC1820Implementer({ from: recipient });

      let cert = await getValidCertificate(this.token, 'issue', owner);
      await this.token.issue(tokenHolder, initialSupply, cert, { from: owner });
    });
    describe('when the transfer is successfull', function () {
      it('transfers the requested amount', async function () {
        let cert = await getValidCertificate(this.token, 'transferWithData', tokenHolder);
        await this.token.transferWithData(to, amount, cert, { from: tokenHolder });
        const senderBalance = await this.token.balanceOf(tokenHolder);
        assert.equal(senderBalance, initialSupply - amount);

        const recipientBalance = await this.token.balanceOf(to);
        assert.equal(recipientBalance, amount);
      });
    });
    describe('when the transfer fails', function () {
      it('sender hook reverts', async function () {
        // Default sender hook failure data for the mock only: 0x1100000000000000000000000000000000000000000000000000000000000000
        await shouldFail.reverting(this.token.transferWithData(to, amount, INVALID_CERTIFICATE_SENDER, { from: tokenHolder }));
      });
      it('recipient hook reverts', async function () {
        // Default recipient hook failure data for the mock only: 0x2200000000000000000000000000000000000000000000000000000000000000
        await shouldFail.reverting(this.token.transferWithData(to, amount, INVALID_CERTIFICATE_RECIPIENT, { from: tokenHolder }));
      });
    });
  });
});
