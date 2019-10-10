import { shouldFail } from 'openzeppelin-test-helpers';
const BigNumber = require('bignumber.js');
const ethers = require('ethers');
const secp256k1 = require('secp256k1');

const MWTINTERESTS = artifacts.require('minterests');
const MWTTOKEN = artifacts.require('MWT');

const CERTIFICATE_SIGNER = '0x669026fd00d99ffdffc7c44968abbaf5777b1bf5';
const CERTIFICATE_SIGNER_PK = '0x91253726a4ff08860547613455e91d8b7cbcfd4afdfe1e2ee7f7ab0c1dede129';

const partitionPerpetual = '0x7065725f30303030303000000000000000000000000000000000000000000000'; // per_000000 in hex
const partitionMidterm = '0x6d69645f30303030303000000000000000000000000000000000000000000000'; // mid_000000 in hex
const partitionLongterm = '0x6c6e675f30303030303000000000000000000000000000000000000000000000'; // lng_000000 in hex

const partitions = [partitionPerpetual];

const DECIMALS = new BigNumber(1000000000000000000); // 10^18

/* Takes the balance as a BigNumber */
const assertBalanceOfByPartition = async (
  _contract,
  _tokenHolder,
  _partition,
  _amount
) => {
  let balanceByPartition = await _contract.balanceOfByPartition(_partition, _tokenHolder);
  assert.equal(balanceByPartition, _amount.toNumber());
};

/* Takes the balance as a BigInteger */
const assertBalanceOf = async (
  _contract,
  _tokenHolder,
  _amount
) => {
  const partitions = await _contract.partitionsOf(_tokenHolder);

  const promises = [];
  partitions.forEach(partition => {
    promises.push(_contract.balanceOfByPartition(partition, _tokenHolder));
  });

  const balances = await Promise.all(promises);
  assert.equal(partitions.length, balances.length);

  const balance = balances.reduce((accumulator, currentValue) => new BigNumber(accumulator.toString()).plus(new BigNumber(currentValue.toString())));
  assert.equal(balance, _amount.toNumber());
};

/* Takes the interests as a BigNumber */
const assertInterestsOf = async (
  _contract,
  _tokenHolder,
  _amount
) => {
  /* Javascript rounds up so we ought to round up the contract values */
  const contractInterests = new BigNumber(Math.round(await _contract.interestsOf(_tokenHolder) / 10000)); // divided by 10^4 so we still have 14 digits
  const computedInterests = new BigNumber(Math.round(_amount / 10000));
  assert.equal(contractInterests.toNumber(), computedInterests.toNumber());
};

const assertIsClaimingInterests = async (
  _contract,
  _tokenHolder,
  _bool,
) => {
  const isClaimingInterests = await _contract.isClaimingInterests(_tokenHolder);
  assert.equal(isClaimingInterests[0], _bool);
};

const assertIsClaimingInterestsCurrency = async (
  _contract,
  _tokenHolder,
  _currency
) => {
  const isClaimingInterests = await _contract.isClaimingInterests(_tokenHolder);
  assert.equal(isClaimingInterests[1], ethers.utils.formatBytes32String(_currency));
};

const assertIsClaimingBonds = async (
  _contract,
  _tokenHolder,
  _bool,
) => {
  const isClaimingBonds = await _contract.isClaimingBonds(_tokenHolder);
  assert.equal(isClaimingBonds[0], _bool);
};

const assertIsClaimingBondsCurrency = async (
  _contract,
  _tokenHolder,
  _currency
) => {
  const isClaimingBonds = await _contract.isClaimingBonds(_tokenHolder);
  assert.equal(isClaimingBonds[1], ethers.utils.formatBytes32String(_currency));
};

/* This generates a valid certificate for a given user (identified by an address)
 * to use a given function (identified by the functionName) */
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
  const msgHash = ethers.utils.solidityKeccak256(['string', 'bytes4', 'bytes32'], ['\x19Ethereum Signed Message:\n32', functionId, nonceAsBytes32]);
  const msg = Buffer.from(msgHash.replace(/0x/g, ''), 'hex');
  const pk = Buffer.from(CERTIFICATE_SIGNER_PK.replace(/0x/g, ''), 'hex');
  const sig = secp256k1.sign(msg, pk);
  const recId = sig.recovery < 27 ? sig.recovery + 27 : sig.recovery;
  return '0x' + recId.toString(16) + sig.signature.toString('hex');
};

/* ======= Bonds interests rates are all multiplied by DECIMALS in order to have 10**18 decimals ======= */

/* Returns the (fixed) midterm bond interests rate */
const getMidtermRate = () => {
  return new BigNumber(DECIMALS.multipliedBy(0.0575).dividedBy(DECIMALS)); // Does what the contract does
};

/* Returns the longterm bond interests rate of someone given how many longterm tokens he holds
 * and for how long he's been holding them */
const getLongtermRate = (
  _balance,
  _holding
) => {
  if (_balance <= 0) {
    return new BigNumber(0);
  }

  if (_holding < 12 * DECIMALS) {
    if (_balance < 800 * DECIMALS) {
      return new BigNumber(DECIMALS.multipliedBy(0.07));
    } if (_balance < 2400 * DECIMALS) {
      return new BigNumber(DECIMALS.multipliedBy(0.073));
    } if (_balance < 7200 * DECIMALS) {
      return new BigNumber(DECIMALS.multipliedBy(0.0749));
    }
    return new BigNumber(DECIMALS.multipliedBy(0.0760));
  } if (_holding < 36 * DECIMALS) {
    if (_balance < 800 * DECIMALS) {
      return new BigNumber(DECIMALS.multipliedBy(0.0730));
    } if (_balance < 2400 * DECIMALS) {
      return new BigNumber(DECIMALS.multipliedBy(0.0745));
    } if (_balance < 7200 * DECIMALS) {
      return new BigNumber(DECIMALS.multipliedBy(0.0756));
    }
    return new BigNumber(DECIMALS.multipliedBy(0.0764));
  } if (_holding < 72 * DECIMALS) {
    if (_balance < 800 * DECIMALS) {
      return new BigNumber(DECIMALS.multipliedBy(0.0749));
    } if (_balance < 2400 * DECIMALS) {
      return new BigNumber(DECIMALS.multipliedBy(0.0757));
    }
    if (_balance < 7200 * DECIMALS) {
      return new BigNumber(DECIMALS.multipliedBy(0.0763));
    }
    return new BigNumber(DECIMALS.multipliedBy(0.0767));
  }
  // if he's been holding them for (more than) 72 months
  if (_balance < 800 * DECIMALS) {
    return new BigNumber(DECIMALS.multipliedBy(0.0760));
  } if (_balance < 2400 * DECIMALS) {
    return new BigNumber(DECIMALS.multipliedBy(0.0764));
  } if (_balance < 7200 * DECIMALS) {
    return new BigNumber(DECIMALS.multipliedBy(0.0767));
  }
  return new BigNumber(DECIMALS.multipliedBy(0.0770));
};

/* Takes the balance and holding as BigNumbers */
const computeLongtermInterests = (
  _balance,
  _holding
) => {
  return getLongtermRate(_balance.toNumber(), _holding.toNumber()).multipliedBy(_balance).dividedBy(12).dividedBy(DECIMALS);
};

/* Returns the perpetual bond interests rate of someone given how many perpetual tokens he holds
 * and for how long he's been holding them */
const getPerpetualRate = (
  _balance,
  _holding
) => {
  if (_balance <= 0) {
    return new BigNumber(0);
  }
  if (_holding < 12 * DECIMALS) {
    if (_balance < 800 * DECIMALS) {
      return new BigNumber(DECIMALS.multipliedBy(0.0850));
    } if (_balance < 2400 * DECIMALS) {
      return new BigNumber(DECIMALS.multipliedBy(0.0888));
    } if (_balance < 7200 * DECIMALS) {
      return new BigNumber(DECIMALS.multipliedBy(0.0911));
    }
    return new BigNumber(DECIMALS.multipliedBy(0.0925));
  } if (_holding < 36 * DECIMALS) {
    if (_balance < 800 * DECIMALS) {
      return new BigNumber(DECIMALS.multipliedBy(0.0888));
    } if (_balance < 2400 * DECIMALS) {
      return new BigNumber(DECIMALS.multipliedBy(0.0906));
    } if (_balance < 7200 * DECIMALS) {
      return new BigNumber(DECIMALS.multipliedBy(0.0919));
    }
    return new BigNumber(DECIMALS.multipliedBy(0.0930));
  } if (_holding < 72 * DECIMALS) {
    if (_balance < 800 * DECIMALS) {
      return new BigNumber(DECIMALS.multipliedBy(0.0911));
    } if (_balance < 2400 * DECIMALS) {
      return new BigNumber(DECIMALS.multipliedBy(0.0919));
    } if (_balance < 7200 * DECIMALS) {
      return new BigNumber(DECIMALS.multipliedBy(0.0927));
    }
    return new BigNumber(DECIMALS.multipliedBy(0.0934));
  }
  // if he's been holding them for (more than) 72 months
  if (_balance < 800 * DECIMALS) {
    return new BigNumber(DECIMALS.multipliedBy(0.0925));
  } if (_balance < 2400 * DECIMALS) {
    return new BigNumber(DECIMALS.multipliedBy(0.0930));
  } if (_balance < 7200 * DECIMALS) {
    return new BigNumber(DECIMALS.multipliedBy(0.0934));
  }
  return new BigNumber(DECIMALS.multipliedBy(0.0937));
};

/* Takes the balance and holding as BigNumbers */
const computePerpetualInterests = (
  _balance,
  _holding
) => {
  return getPerpetualRate(_balance.toNumber(), _holding.toNumber()).multipliedBy(_balance).dividedBy(12).dividedBy(DECIMALS);
};

/* If balance increases, the holding of perpetual and/or longterm bonds has to be adjusted */
const adjustHolding = (
  _holding,
  _balance,
  _delta
) => {
  let adjustmentFactor = new BigNumber(_delta.dividedBy(_balance).multipliedBy(DECIMALS));
  return (DECIMALS.minus(adjustmentFactor)).multipliedBy(_holding.plus(DECIMALS)).dividedBy(DECIMALS);
};

contract('Interests contract', async accounts => {
  beforeEach(async function () {
    // We'll need to have both our contracts instanciated in any case
    // second address of the HD wallet is controller
    this.tokenContract = await MWTTOKEN.new('Montessori Worlwide Token', 'MWT', 1, [accounts[1]], CERTIFICATE_SIGNER, partitions);
    this.interestsContract = await MWTINTERESTS.new();
    this.validIssueCert = async (_address) => getValidCertificate(this.tokenContract, 'issueByPartition', _address);
    this.validRedeemCert = async (_address) => getValidCertificate(this.tokenContract, 'redeemByPartition', _address);
  });
  describe('when updateInterests is called', function () {
    it('increases interests according to the table when investor\'s midterm balance is non 0', async function () {
      const midtermBalance = DECIMALS.multipliedBy(1000);
      let interests = new BigNumber(0);
      let cert = await this.validIssueCert(accounts[0]);
      await this.tokenContract.issueByPartition(partitionMidterm, accounts[2], midtermBalance.toFixed(), cert, { from: accounts[0] });
      await assertBalanceOfByPartition(this.tokenContract, accounts[2], partitionMidterm, midtermBalance);
      await assertBalanceOf(this.tokenContract, accounts[2], midtermBalance);
      await assertInterestsOf(this.interestsContract, accounts[2], 0);
      // Test 1 month later
      await this.interestsContract.updateInterests(accounts[2], midtermBalance.toFixed(), 0, 0, { from: accounts[0] });
      interests = interests.plus(midtermBalance.multipliedBy(getMidtermRate()).dividedBy(12));
      await assertInterestsOf(this.interestsContract, accounts[2], interests);
      // Test 1 year later
      for (let i = 1; i < 12; i++) {
        await this.interestsContract.updateInterests(accounts[2], midtermBalance.toFixed(), 0, 0, { from: accounts[0] });
        interests = interests.plus(midtermBalance.multipliedBy(getMidtermRate()).dividedBy(12));
      }
      await assertInterestsOf(this.interestsContract, accounts[2], interests);
    });
    it('increases interests according to the table when investor\'s midterm balance increases', async function () {
      let midtermBalance = DECIMALS.multipliedBy(1000);
      let interests = new BigNumber(0);
      let cert = await this.validIssueCert(accounts[0]);
      await this.tokenContract.issueByPartition(partitionMidterm, accounts[2], midtermBalance.toFixed(), cert, { from: accounts[0] });
      await assertBalanceOfByPartition(this.tokenContract, accounts[2], partitionMidterm, midtermBalance);
      await assertBalanceOf(this.tokenContract, accounts[2], midtermBalance);
      await assertInterestsOf(this.interestsContract, accounts[2], interests);
      // Test 1 year later
      for (let i = 0; i < 12; i++) {
        if (i === 5) {
          const newMidtermBonds = 200;
          cert = await this.validIssueCert(accounts[0]);
          await this.tokenContract.issueByPartition(partitionMidterm, accounts[2], DECIMALS.multipliedBy(newMidtermBonds), cert, { from: accounts[0] });
          midtermBalance = midtermBalance.plus(DECIMALS.multipliedBy(newMidtermBonds));
        } else if (i === 8) {
          const newMidtermBonds = 350;
          cert = await this.validIssueCert(accounts[0]);
          await this.tokenContract.issueByPartition(partitionMidterm, accounts[2], DECIMALS.multipliedBy(newMidtermBonds), cert, { from: accounts[0] });
          midtermBalance = midtermBalance.plus(DECIMALS.multipliedBy(newMidtermBonds));
        }
        await this.interestsContract.updateInterests(accounts[2], midtermBalance.toFixed(), 0, 0, { from: accounts[0] });
        interests = interests.plus(midtermBalance.multipliedBy(getMidtermRate()).dividedBy(12));
      }
      await assertInterestsOf(this.interestsContract, accounts[2], interests);
    });
    it('decreases interests when investor\'s midterm balance decreases', async function () {
      let midtermBalance = DECIMALS.multipliedBy(1000);
      let interests = new BigNumber(0);
      let cert = await this.validIssueCert(accounts[0]);
      await this.tokenContract.issueByPartition(partitionMidterm, accounts[2], midtermBalance.toFixed(), cert, { from: accounts[0] });
      await assertBalanceOfByPartition(this.tokenContract, accounts[2], partitionMidterm, midtermBalance);
      await assertBalanceOf(this.tokenContract, accounts[2], midtermBalance);
      await assertInterestsOf(this.interestsContract, accounts[2], interests);
      // Test 1 year later
      for (let i = 0; i < 12; i++) {
        if (i === 5) {
          const removedMidtermBonds = 350;
          cert = await this.validRedeemCert(accounts[2]);
          await this.tokenContract.redeemByPartition(partitionMidterm, DECIMALS.multipliedBy(removedMidtermBonds), cert, { from: accounts[2] });
          midtermBalance = midtermBalance.minus(DECIMALS.multipliedBy(removedMidtermBonds));
        } else if (i === 8) {
          const removedMidtermBonds = 400;
          cert = await this.validRedeemCert(accounts[2]);
          await this.tokenContract.redeemByPartition(partitionMidterm, DECIMALS.multipliedBy(removedMidtermBonds), cert, { from: accounts[2] });
          midtermBalance = midtermBalance.minus(DECIMALS.multipliedBy(removedMidtermBonds));
        }
        await this.interestsContract.updateInterests(accounts[2], midtermBalance.toFixed(), 0, 0, { from: accounts[0] });
        interests = interests.plus(midtermBalance.multipliedBy(getMidtermRate()).dividedBy(12));
      }
      await assertInterestsOf(this.interestsContract, accounts[2], interests);
    });
    it('increases interests according to the table when investor\'s longterm balance is non 0', async function () {
      let lngtermBalance = DECIMALS.multipliedBy(1274); // let's test with odd values, not "42" or "1000"
      let holding = new BigNumber(0);
      let interests = new BigNumber(0);
      let cert = await this.validIssueCert(accounts[0]);
      await this.tokenContract.issueByPartition(partitionLongterm, accounts[2], lngtermBalance.toFixed(), cert, { from: accounts[0] });
      await assertBalanceOfByPartition(this.tokenContract, accounts[2], partitionLongterm, lngtermBalance);
      await assertBalanceOf(this.tokenContract, accounts[2], lngtermBalance);
      await assertInterestsOf(this.interestsContract, accounts[2], interests);
      // Test 1 year later
      for (let i = 0; i < 12; i++) {
        await this.interestsContract.updateInterests(accounts[2], 0, lngtermBalance.toFixed(), 0, { from: accounts[0] });
        holding = holding.plus(DECIMALS);
        interests = interests.plus(computeLongtermInterests(lngtermBalance, holding));
      }
      await assertInterestsOf(this.interestsContract, accounts[2], interests);
      // Test 2 years later
      for (let i = 12; i < 24; i++) {
        await this.interestsContract.updateInterests(accounts[2], 0, lngtermBalance.toFixed(), 0, { from: accounts[0] });
        holding = holding.plus(DECIMALS);
        interests = interests.plus(computeLongtermInterests(lngtermBalance, holding));
      }
      await assertInterestsOf(this.interestsContract, accounts[2], interests);
      // Test 3 years later (and beyond)
      for (let i = 24; i < 48; i++) {
        await this.interestsContract.updateInterests(accounts[2], 0, lngtermBalance.toFixed(), 0, { from: accounts[0] });
        holding = holding.plus(DECIMALS);
        interests = interests.plus(computeLongtermInterests(lngtermBalance, holding));
      }
      await assertInterestsOf(this.interestsContract, accounts[2], interests);
    });
    it('increases interests according to the table when investor\'s longterm balance increases', async function () {
      let lngtermBalance = DECIMALS.multipliedBy(4398); // Same as above, let's test with odd balances
      let holding = new BigNumber(0);
      let interests = new BigNumber(0);
      let cert = await this.validIssueCert(accounts[0]);
      await this.tokenContract.issueByPartition(partitionLongterm, accounts[2], lngtermBalance.toFixed(), cert, { from: accounts[0] });
      await assertBalanceOfByPartition(this.tokenContract, accounts[2], partitionLongterm, lngtermBalance);
      await assertBalanceOf(this.tokenContract, accounts[2], lngtermBalance);
      await assertInterestsOf(this.interestsContract, accounts[2], interests);
      // Test 1 year later
      for (let i = 0; i < 24; i++) {
        if (i === 4) {
          let balanceIncrease = DECIMALS.multipliedBy(247);
          cert = await this.validIssueCert(accounts[0]);
          await this.tokenContract.issueByPartition(partitionLongterm, accounts[2], balanceIncrease.toFixed(), cert, { from: accounts[0] });
          lngtermBalance = lngtermBalance.plus(balanceIncrease);
          holding = adjustHolding(holding, lngtermBalance, balanceIncrease);
        } else if (i === 9) {
          let balanceIncrease = DECIMALS.multipliedBy(428);
          cert = await this.validIssueCert(accounts[0]);
          await this.tokenContract.issueByPartition(partitionLongterm, accounts[2], balanceIncrease.toFixed(), cert, { from: accounts[0] });
          lngtermBalance = lngtermBalance.plus(balanceIncrease);
          holding = adjustHolding(holding, lngtermBalance, balanceIncrease);
        } else {
          holding = holding.plus(DECIMALS);
        }
        await this.interestsContract.updateInterests(accounts[2], 0, lngtermBalance.toFixed(), 0, { from: accounts[0] });
        interests = interests.plus(computeLongtermInterests(lngtermBalance, holding));
      }
      await assertInterestsOf(this.interestsContract, accounts[2], interests);
    });
    it('increases interests according to the table when investor\'s perpetual balance is non 0', async function () {
      const perpetualBalance = DECIMALS.multipliedBy(2431); // real world values
      let holding = new BigNumber(0);
      let interests = new BigNumber(0);
      let cert = await this.validIssueCert(accounts[0]);
      await this.tokenContract.issueByPartition(partitionPerpetual, accounts[2], perpetualBalance.toFixed(), cert, { from: accounts[0] });
      await assertBalanceOfByPartition(this.tokenContract, accounts[2], partitionPerpetual, perpetualBalance);
      await assertBalanceOf(this.tokenContract, accounts[2], perpetualBalance);
      await assertInterestsOf(this.interestsContract, accounts[2], interests);
      // Test 1 year later
      for (let i = 0; i < 12; i++) {
        await this.interestsContract.updateInterests(accounts[2], 0, 0, perpetualBalance.toFixed(), { from: accounts[0] });
        holding = holding.plus(DECIMALS);
        interests = interests.plus(computePerpetualInterests(perpetualBalance, holding));
      }
      await assertInterestsOf(this.interestsContract, accounts[2], interests);
      // Test 2 years later
      for (let i = 12; i < 24; i++) {
        await this.interestsContract.updateInterests(accounts[2], 0, 0, perpetualBalance.toFixed(), { from: accounts[0] });
        holding = holding.plus(DECIMALS);
        interests = interests.plus(computePerpetualInterests(perpetualBalance, holding));
      }
      await assertInterestsOf(this.interestsContract, accounts[2], interests);
      // Test 3 years later (and beyond)
      for (let i = 24; i < 48; i++) {
        await this.interestsContract.updateInterests(accounts[2], 0, 0, perpetualBalance.toFixed(), { from: accounts[0] });
        holding = holding.plus(DECIMALS);
        interests = interests.plus(computePerpetualInterests(perpetualBalance, holding));
      }
      await assertInterestsOf(this.interestsContract, accounts[2], interests);
    });
    it('increases interests according to the table when investor\'s perpetual balance increases', async function () {
      let perpetualBalance = DECIMALS.multipliedBy(507); // Same as above, let's test with odd balances
      let holding = new BigNumber(0);
      let interests = new BigNumber(0);
      let cert = await this.validIssueCert(accounts[0]);
      await this.tokenContract.issueByPartition(partitionPerpetual, accounts[2], perpetualBalance.toFixed(), cert, { from: accounts[0] });
      await assertBalanceOfByPartition(this.tokenContract, accounts[2], partitionPerpetual, perpetualBalance);
      await assertBalanceOf(this.tokenContract, accounts[2], perpetualBalance);
      await assertInterestsOf(this.interestsContract, accounts[2], interests);
      // Test 1 year later
      for (let i = 0; i < 12; i++) {
        if (i === 4) {
          let balanceIncrease = DECIMALS.multipliedBy(1189);
          cert = await this.validIssueCert(accounts[0]);
          await this.tokenContract.issueByPartition(partitionPerpetual, accounts[2], balanceIncrease.toFixed(), cert, { from: accounts[0] });
          perpetualBalance = perpetualBalance.plus(balanceIncrease);
          holding = adjustHolding(holding, perpetualBalance, balanceIncrease);
        } else if (i === 9) {
          let balanceIncrease = DECIMALS.multipliedBy(206);
          cert = await this.validIssueCert(accounts[0]);
          await this.tokenContract.issueByPartition(partitionPerpetual, accounts[2], balanceIncrease.toFixed(), cert, { from: accounts[0] });
          perpetualBalance = perpetualBalance.plus(balanceIncrease);
          holding = adjustHolding(holding, perpetualBalance, balanceIncrease);
        } else {
          holding = holding.plus(DECIMALS);
        }
        await this.interestsContract.updateInterests(accounts[2], 0, 0, perpetualBalance.toFixed(), { from: accounts[0] });
        interests = interests.plus(computePerpetualInterests(perpetualBalance, holding));
      }
      await assertInterestsOf(this.interestsContract, accounts[2], interests);
    });
    it('behaves accordingly with the interests table when investor has multiple bonds and the balances varies', async function () {
      const midterm = {
        'balance': DECIMALS.multipliedBy(616),
        'holding': new BigNumber(0),
      };
      const longterm = {
        'balance': DECIMALS.multipliedBy(1439),
        'holding': new BigNumber(0),
        // Did the balance increase since last month ? It's used to adjust holding
        'balanceOld': new BigNumber(0),
      };
      const perpetual = {
        'balance': new BigNumber(0),
        'holding': new BigNumber(0),
        'balanceOld': new BigNumber(0),
      };
      let interests = new BigNumber(0);
      let cert = await this.validIssueCert(accounts[0]);
      await this.tokenContract.issueByPartition(partitionMidterm, accounts[2], midterm.balance.toFixed(), cert, { from: accounts[0] });
      cert = await this.validIssueCert(accounts[0]);
      await this.tokenContract.issueByPartition(partitionLongterm, accounts[2], longterm.balance.toFixed(), cert, { from: accounts[0] });
      cert = await this.validIssueCert(accounts[0]);
      // In case we change the initial balance
      await this.tokenContract.issueByPartition(partitionPerpetual, accounts[2], perpetual.balance.toFixed(), cert, { from: accounts[0] });
      await assertBalanceOfByPartition(this.tokenContract, accounts[2], partitionMidterm, midterm.balance);
      await assertBalanceOfByPartition(this.tokenContract, accounts[2], partitionLongterm, longterm.balance);
      await assertBalanceOfByPartition(this.tokenContract, accounts[2], partitionPerpetual, perpetual.balance);
      await assertBalanceOf(this.tokenContract, accounts[2], midterm.balance.plus(longterm.balance).plus(perpetual.balance));
      await assertInterestsOf(this.interestsContract, accounts[2], interests);
      // Let's pass four years
      for (let i = 0; i < 1; i++) {
        // After 6 months our guinea pig decides to buy some perpetual bonds
        if (i === 6) {
          perpetual.balance = perpetual.balance.plus(DECIMALS.multipliedBy(1402));
          cert = await this.validIssueCert(accounts[0]);
          await this.tokenContract.issueByPartition(partitionPerpetual, accounts[2], perpetual.balance.minus(perpetual.balanceOld).toFixed(), cert, { from: accounts[0] });
        }
        // Then he buys some more longterm
        if (i === 8) {
          longterm.balance = longterm.balance.plus(DECIMALS.multipliedBy(398));
          cert = await this.validIssueCert(accounts[0]);
          await this.tokenContract.issueByPartition(partitionLongterm, accounts[2], longterm.balance.minus(longterm.balanceOld).toFixed(), cert, { from: accounts[0] });
        }
        // And at the 27th month he finally sells some midterm and longterm bonds to buy some perpetual bonds
        if (i === 27) {
          midterm.balance = midterm.balance.minus(DECIMALS.multipliedBy(250));
          longterm.balance = longterm.balance.minus(DECIMALS.multipliedBy(994));
          perpetual.balance = perpetual.balance.plus(DECIMALS.multipliedBy(1000));
          cert = await this.validRedeemCert(accounts[2]);
          await this.tokenContract.redeemByPartition(partitionMidterm, DECIMALS.multipliedBy(250).toFixed(), cert, { from: accounts[2] });
          cert = await this.validRedeemCert(accounts[2]);
          await this.tokenContract.redeemByPartition(partitionLongterm, longterm.balanceOld.minus(longterm.balance).toFixed(), cert, { from: accounts[2] });
          cert = await this.validIssueCert(accounts[0]);
          await this.tokenContract.issueByPartition(partitionPerpetual, accounts[2], perpetual.balance.minus(perpetual.balanceOld).toFixed(), cert, { from: accounts[0] });
        }

        if (midterm.balance > 0) {
          midterm.holding = midterm.holding.plus(DECIMALS);
        }
        if (longterm.balance > 0) {
          if (longterm.balance > longterm.balanceOld) {
            longterm.holding = adjustHolding(longterm.holding, longterm.balance, (longterm.balance).minus(longterm.balanceOld));
          } else {
            longterm.holding = longterm.holding.plus(DECIMALS);
          }
        }
        if (perpetual.balance > 0) {
          if (perpetual.balance > perpetual.balanceOld) {
            perpetual.holding = adjustHolding(perpetual.holding, perpetual.balance, (perpetual.balance).minus(perpetual.balanceOld));
          } else {
            perpetual.holding = perpetual.holding.plus(DECIMALS);
          }
        }
        longterm.balanceOld = longterm.balance;
        perpetual.balanceOld = perpetual.balance;

        interests = interests.plus(midterm.balance.dividedBy(12).multipliedBy(getMidtermRate()));
        interests = interests.plus(computeLongtermInterests(longterm.balance, longterm.holding));
        interests = interests.plus(computePerpetualInterests(perpetual.balance, perpetual.holding));
        await this.interestsContract.updateInterests(accounts[2], midterm.balance.toFixed(), longterm.balance.toFixed(), perpetual.balance.toFixed(), { from: accounts[0] });
      }
      await assertInterestsOf(this.interestsContract, accounts[2], interests);
    });
    it('test referee balance checking and interests when current balance lower than referees', async function () {
      const midAmount = DECIMALS.multipliedBy(100);
      const lngAmount = DECIMALS.multipliedBy(500);
      const perAmount = DECIMALS.multipliedBy(0);
      const midRefereeAmount = DECIMALS.multipliedBy(200);
      const lngRefereeAmount = DECIMALS.multipliedBy(400);
      const perRefereeAmount = DECIMALS.multipliedBy(600);
      const computedInterests = midAmount.multipliedBy(0.0575).multipliedBy(1.05).plus(lngAmount.minus(lngRefereeAmount).multipliedBy(0.07)).plus(lngRefereeAmount.multipliedBy(0.0735)).dividedBy(12);

      // referee balances initialization
      await this.interestsContract.setRefereeAmount(accounts[2], midRefereeAmount, lngRefereeAmount, perRefereeAmount);
      const retrievedMidInfos = await this.interestsContract.midtermBondInfosOf(accounts[2]);
      const retrievedLngInfos = await this.interestsContract.longtermBondInfosOf(accounts[2]);
      const retrievedPerInfos = await this.interestsContract.perpetualBondInfosOf(accounts[2]);
      assert.equal(retrievedMidInfos[2], 200000000000000000000);
      assert.equal(retrievedLngInfos[2], 400000000000000000000);
      assert.equal(retrievedPerInfos[2], 600000000000000000000);
      //  updates interests (and referee balances by the way)
      const { logs } = await this.interestsContract.updateInterests(accounts[2], midAmount, lngAmount, perAmount);
      const retrievedMidInfos2 = await this.interestsContract.midtermBondInfosOf(accounts[2]);
      const retrievedLngInfos2 = await this.interestsContract.longtermBondInfosOf(accounts[2]);
      const retrievedPerInfos2 = await this.interestsContract.perpetualBondInfosOf(accounts[2]);
      assert.equal(retrievedMidInfos2[0], 100000000000000000000);
      assert.equal(retrievedLngInfos2[0], 500000000000000000000);
      assert.equal(retrievedPerInfos2[0], 0);
      //    mid : referee balance should be decreased
      assert.equal(retrievedMidInfos2[2], 100000000000000000000);
      //    lng : referee balance should remain the same
      assert.equal(retrievedLngInfos2[2], 400000000000000000000);
      //    per : referee balance should be reset
      assert.equal(retrievedPerInfos2[2], 0);
      //  Interests checking
      await assertInterestsOf(this.interestsContract, accounts[2], computedInterests);

      //  ModifiedReferee event should rise because a referee balance has been changed
      assert.equal(logs.length, 4);
      assert.equal(logs[0].event, 'ModifiedReferee');
      assert.equal(logs[0].args.investor, accounts[2]);
      assert.equal(logs[0].args.midAmount, 100000000000000000000);
      assert.equal(logs[0].args.lngAmount, 400000000000000000000);
      assert.equal(logs[0].args.perAmount, 0);
    });


  });
  describe('when setInterests is called', function () {
    it('set custom interests balances', async function () {
      const customInterests = DECIMALS.multipliedBy(200);
      const customInterests2 = DECIMALS.multipliedBy(1000);
      await this.interestsContract.setInterests(accounts[2], customInterests.toFixed());
      await assertInterestsOf(this.interestsContract, accounts[2], customInterests);
      await this.interestsContract.setInterests(accounts[2], customInterests2.toFixed());
      await assertInterestsOf(this.interestsContract, accounts[2], customInterests2);
    });
  });
  describe('when updateReferral is called', function () {
    it('adds token accordingly with the referee bonus amount', async function () {
      const referer = accounts[3];
      const referee = accounts[4];
      const midAmount = DECIMALS.multipliedBy(100);
      const lngAmount = DECIMALS.multipliedBy(200);
      const perAmount = DECIMALS.multipliedBy(300);
      const percent = new BigNumber(5);

      const { logs } = await this.interestsContract.updateReferralInfos(referer, referee, percent.toFixed(), midAmount.toFixed(), lngAmount.toFixed(), perAmount.toFixed());
      const computedRefererInterests = new BigNumber(await this.interestsContract.interestsOf(referer));
      assert.equal(computedRefererInterests.dividedBy(DECIMALS).toNumber(), percent.dividedBy(100).multipliedBy(midAmount.plus(lngAmount).plus(perAmount)).dividedBy(DECIMALS).toNumber());

      assert.equal(logs.length, 3);
      assert.equal(logs[0].event, 'UpdatedInterests');
      assert.equal(logs[0].args.investor, referer);
      assert.equal(new BigNumber(logs[0].args.interests.toString()).toFixed(), DECIMALS.multipliedBy(30).toFixed());

      assert.equal(logs[1].event, 'ModifiedReferee');
      assert.equal(logs[1].args.investor, referee);
      assert.equal(new BigNumber(logs[1].args.perAmount.toString()).toFixed(), perAmount.toFixed());
      assert.equal(new BigNumber(logs[1].args.midAmount.toString()).toFixed(), midAmount.toFixed());
      assert.equal(new BigNumber(logs[1].args.lngAmount.toString()).toFixed(), lngAmount.toFixed());

      assert.equal(logs[2].event, 'Refered');
      assert.equal(logs[2].args.referer, referer);
      assert.equal(logs[2].args.referee, referee);
      assert.equal(new BigNumber(logs[1].args.perAmount.toString()).toFixed(), perAmount.toFixed());
      assert.equal(new BigNumber(logs[1].args.midAmount.toString()).toFixed(), midAmount.toFixed());
      assert.equal(new BigNumber(logs[1].args.lngAmount.toString()).toFixed(), lngAmount.toFixed());

      const computedRefereeBalanceMid = await this.interestsContract.midtermBondInfosOf(referee);
      assert.equal(new BigNumber(computedRefereeBalanceMid[2]).toNumber(), midAmount.toNumber());
      const computedRefereeBalanceLng = await this.interestsContract.longtermBondInfosOf(referee);
      assert.equal(new BigNumber(computedRefereeBalanceLng[2]).toNumber(), lngAmount.toNumber());
      const computedRefereeBalancePer = await this.interestsContract.perpetualBondInfosOf(referee);
      assert.equal(new BigNumber(computedRefereeBalancePer[2]).toNumber(), perAmount.toNumber());
    });
    it('fails if the given rate is not a number between 0 and 100', async function () {
      await shouldFail.reverting(this.interestsContract.updateReferralInfos(accounts[3], accounts[4], 0, 1, 1, 1));
    });
    it('fails if the referee or the referer is not valid', async function () {
      // referer == referee
      await shouldFail.reverting(this.interestsContract.updateReferralInfos(accounts[3], accounts[3], 1, 1, 1, 1));
      // referer == address(0)
      await shouldFail.reverting(this.interestsContract.updateReferralInfos('0x0'.padEnd(42, '0'), accounts[3], 1, 1, 1, 1));
      // referee == address(0)
      await shouldFail.reverting(this.interestsContract.updateReferralInfos(accounts[3], '0x0'.padEnd(42, '0'), 1, 1, 1, 1));
    });
  });
  describe('Testing methods allowing third party to interact with interests balance of investors', function () {
    it('Set a third party as InterestsController', async function () {
      await assert(this.interestsContract.isInterestsController(accounts[4]), false);
      await this.interestsContract.setInterestsController(accounts[4], true);
      await assert(this.interestsContract.isInterestsController(accounts[4]), true);
    });
    it('checks claiming methods', async function () {
      const interests = DECIMALS.multipliedBy(1000);
      const interests2 = DECIMALS.multipliedBy(2000);
      // investor have interests and is not claiming
      await this.interestsContract.setInterests(accounts[1], interests.toFixed());
      await this.interestsContract.setInterests(accounts[2], interests2.toFixed());
      // checks investors interests
      await assertInterestsOf(this.interestsContract, accounts[1], interests);
      await assertInterestsOf(this.interestsContract, accounts[2], interests2);
      // checks investors claiming status
      await assertIsClaimingInterests(this.interestsContract, accounts[1], false);
      await assertIsClaimingInterests(this.interestsContract, accounts[2], false);

      // investor wants to be paid in euros
      await this.interestsContract.claimInterests(true, web3.utils.utf8ToHex('eur'), { from: accounts[1] });
      await this.interestsContract.claimInterests(true, web3.utils.utf8ToHex('eth'), { from: accounts[2] });
      // checks investors claiming status
      await assertIsClaimingInterests(this.interestsContract, accounts[1], true);
      await assertIsClaimingInterests(this.interestsContract, accounts[2], true);
      // checks investors claiming currency
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[1], 'eur');
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[2], 'eth');

      // an interest controller is declared
      await this.interestsContract.setInterestsController(accounts[4], true);
      // unauthorized controller
      await shouldFail.reverting(this.interestsContract.payInterests([accounts[1], accounts[2]], { from: accounts[5] }));

      // a controller notifies an investor that interests have been paid
      await this.interestsContract.payInterests([accounts[1], accounts[2]], { from: accounts[4] });
      // checks wether interests balance has been reset
      await assertInterestsOf(this.interestsContract, accounts[1], 0);
      await assertInterestsOf(this.interestsContract, accounts[2], 0);

      // once paid, investor is not claiming anymore and the currency is reset
      await assertIsClaimingInterests(this.interestsContract, accounts[1], false);
      await assertIsClaimingInterests(this.interestsContract, accounts[2], false);
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[1], '');
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[2], '');
    });
    it('checks batch payout process', async function () {
      const interests = DECIMALS.multipliedBy(1000);
      const interests2 = DECIMALS.multipliedBy(2000);
      // investors 1 and 2 have interests but only investor 1 is claiming
      await this.interestsContract.setInterests(accounts[1], interests.toFixed());
      await this.interestsContract.setInterests(accounts[2], interests2.toFixed());
      await assertInterestsOf(this.interestsContract, accounts[1], interests);
      await assertInterestsOf(this.interestsContract, accounts[2], interests2);
      await assertIsClaimingInterests(this.interestsContract, accounts[1], false);
      await assertIsClaimingInterests(this.interestsContract, accounts[2], false);

      // investor wants to be paid in euros
      await this.interestsContract.claimInterests(true, web3.utils.utf8ToHex('eur'), { from: accounts[1] });
      // checks investors claiming status
      await assertIsClaimingInterests(this.interestsContract, accounts[1], true);
      await assertIsClaimingInterests(this.interestsContract, accounts[2], false);
      // checks investors claiming currency
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[1], 'eur');
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[2], '');

      // an interest controller is declared
      await this.interestsContract.setInterestsController(accounts[4], true);
      // unauthorized controller
      await shouldFail.reverting(this.interestsContract.payInterests([accounts[1]], { from: accounts[5] }));

      // a controller makes payout but got wrong on the actual claiming investors
      await shouldFail.reverting(this.interestsContract.payInterests([accounts[1], accounts[2]], { from: accounts[4] }));
      // checks wether interests balance has correctly been untouched
      await assertInterestsOf(this.interestsContract, accounts[1], interests);
      await assertInterestsOf(this.interestsContract, accounts[2], interests2);

      // tx should roll back to the initial state
      await assertIsClaimingInterests(this.interestsContract, accounts[1], true);
      await assertIsClaimingInterests(this.interestsContract, accounts[2], false);
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[1], 'eur');
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[2], '');
    });
    it('checks batch payout process events', async function () {
      const interests = DECIMALS.multipliedBy(1000);
      const interests2 = DECIMALS.multipliedBy(2000);
      const interests3 = DECIMALS.multipliedBy(3000);

      // investors 1, 2 and 3 have interests
      await this.interestsContract.setInterests(accounts[1], interests.toFixed());
      await this.interestsContract.setInterests(accounts[2], interests2.toFixed());
      await this.interestsContract.setInterests(accounts[3], interests3.toFixed());
      await assertInterestsOf(this.interestsContract, accounts[1], interests);
      await assertInterestsOf(this.interestsContract, accounts[2], interests2);
      await assertInterestsOf(this.interestsContract, accounts[3], interests3);
      await assertIsClaimingInterests(this.interestsContract, accounts[1], false);
      await assertIsClaimingInterests(this.interestsContract, accounts[2], false);
      await assertIsClaimingInterests(this.interestsContract, accounts[3], false);

      // investors wants to be paid in euros or eth
      await this.interestsContract.claimInterests(true, web3.utils.utf8ToHex('eur'), { from: accounts[1] });
      await this.interestsContract.claimInterests(true, web3.utils.utf8ToHex('eth'), { from: accounts[2] });
      await this.interestsContract.claimInterests(true, web3.utils.utf8ToHex('eth'), { from: accounts[3] });
      // checks investors claiming status
      await assertIsClaimingInterests(this.interestsContract, accounts[1], true);
      await assertIsClaimingInterests(this.interestsContract, accounts[2], true);
      await assertIsClaimingInterests(this.interestsContract, accounts[3], true);
      // checks investors claiming currency
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[1], 'eur');
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[2], 'eth');
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[3], 'eth');

      // an interest controller is declared
      await this.interestsContract.setInterestsController(accounts[4], true);
      // unauthorized controller
      await shouldFail.reverting(this.interestsContract.payInterests([accounts[1]], { from: accounts[5] }));

      // a controller set interests as paid for each investor
      const { logs } = await this.interestsContract.payInterests([accounts[1], accounts[2], accounts[3]], { from: accounts[4] });

      // checks wether interests balance has been reset
      await assertInterestsOf(this.interestsContract, accounts[1], 0);
      await assertInterestsOf(this.interestsContract, accounts[2], 0);
      await assertInterestsOf(this.interestsContract, accounts[3], 0);

      // once paid, investors are not claiming anymore and the currency is reset
      await assertIsClaimingInterests(this.interestsContract, accounts[1], false);
      await assertIsClaimingInterests(this.interestsContract, accounts[2], false);
      await assertIsClaimingInterests(this.interestsContract, accounts[3], false);
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[1], '');
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[2], '');
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[3], '');

      assert.equal(logs.length, 9);
      assert.equal(logs[0].event, 'ModifiedClaimingInterests');
      assert.equal(logs[0].args.investor, accounts[1]);
      assert.equal(logs[0].args.claiming, false);
      assert.equal(logs[0].args.currency, ethers.utils.formatBytes32String(''));

      assert.equal(logs[1].event, 'WillBePaidInterests');
      assert.equal(logs[1].args.investor, accounts[1]);
      assert.equal(new BigNumber(logs[1].args.balanceInterests.toString()).toFixed(), interests.toFixed());

      assert.equal(logs[2].event, 'UpdatedInterests');
      assert.equal(logs[2].args.investor, accounts[1]);
      assert.equal(logs[2].args.interests, 0);

      assert.equal(logs[3].event, 'ModifiedClaimingInterests');
      assert.equal(logs[3].args.investor, accounts[2]);
      assert.equal(logs[3].args.claiming, false);
      assert.equal(logs[3].args.currency, ethers.utils.formatBytes32String(''));

      assert.equal(logs[4].event, 'WillBePaidInterests');
      assert.equal(logs[4].args.investor, accounts[2]);
      assert.equal(new BigNumber(logs[4].args.balanceInterests.toString()).toFixed(), interests2.toFixed());

      assert.equal(logs[5].event, 'UpdatedInterests');
      assert.equal(logs[5].args.investor, accounts[2]);
      assert.equal(logs[5].args.interests, 0);

      assert.equal(logs[6].event, 'ModifiedClaimingInterests');
      assert.equal(logs[6].args.investor, accounts[3]);
      assert.equal(logs[6].args.claiming, false);
      assert.equal(logs[6].args.currency, ethers.utils.formatBytes32String(''));

      assert.equal(logs[7].event, 'WillBePaidInterests');
      assert.equal(logs[7].args.investor, accounts[3]);
      assert.equal(new BigNumber(logs[7].args.balanceInterests.toString()).toFixed(), interests3.toFixed());

      assert.equal(logs[8].event, 'UpdatedInterests');
      assert.equal(logs[8].args.investor, accounts[3]);
      assert.equal(logs[8].args.interests, 0);
    });
    it('checks batch payout process events when reverting', async function () {
      const interests = DECIMALS.multipliedBy(1000);
      const interests2 = DECIMALS.multipliedBy(2000);
      const interests3 = DECIMALS.multipliedBy(3000);

      // investors 1, 2 and 3 have interests but only investors 1 and 3 are claiming
      await this.interestsContract.setInterests(accounts[1], interests.toFixed());
      await this.interestsContract.setInterests(accounts[2], interests2.toFixed());
      await this.interestsContract.setInterests(accounts[3], interests3.toFixed());
      await assertInterestsOf(this.interestsContract, accounts[1], interests);
      await assertInterestsOf(this.interestsContract, accounts[2], interests2);
      await assertInterestsOf(this.interestsContract, accounts[3], interests3);
      await assertIsClaimingInterests(this.interestsContract, accounts[1], false);
      await assertIsClaimingInterests(this.interestsContract, accounts[2], false);
      await assertIsClaimingInterests(this.interestsContract, accounts[3], false);

      // investors 1 and 3 wants to be paid in euros or eth
      await this.interestsContract.claimInterests(true, web3.utils.utf8ToHex('eur'), { from: accounts[1] });
      await this.interestsContract.claimInterests(true, web3.utils.utf8ToHex('eth'), { from: accounts[3] });
      // checks investors claiming status
      await assertIsClaimingInterests(this.interestsContract, accounts[1], true);
      await assertIsClaimingInterests(this.interestsContract, accounts[2], false);
      await assertIsClaimingInterests(this.interestsContract, accounts[3], true);
      // checks investors claiming currency
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[1], 'eur');
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[2], '');
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[3], 'eth');

      // an interest controller is declared
      await this.interestsContract.setInterestsController(accounts[4], true);
      // unauthorized controller
      await shouldFail.reverting(this.interestsContract.payInterests([accounts[1]], { from: accounts[5] }));

      // a controller makes payout but got wrong on the actual claiming investors
      await shouldFail.reverting(this.interestsContract.payInterests([accounts[1], accounts[2], accounts[3]], { from: accounts[4] }));

      // checks wether interests balance has correctly been untouched
      await assertInterestsOf(this.interestsContract, accounts[1], interests);
      await assertInterestsOf(this.interestsContract, accounts[2], interests2);
      await assertInterestsOf(this.interestsContract, accounts[3], interests3);

      // tx should roll back to the initial state
      await assertIsClaimingInterests(this.interestsContract, accounts[1], true);
      await assertIsClaimingInterests(this.interestsContract, accounts[2], false);
      await assertIsClaimingInterests(this.interestsContract, accounts[3], true);
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[1], 'eur');
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[2], '');
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[3], 'eth');
    });
    it('checks claiming thresholds', async function () {
      const interests = DECIMALS.multipliedBy(10);
      // investor have interests and is not claiming
      await this.interestsContract.setInterests(accounts[1], interests.toFixed());

      // checks investor interests
      await assertInterestsOf(this.interestsContract, accounts[1], interests);

      // checks investor claiming status
      await assertIsClaimingInterests(this.interestsContract, accounts[1], false);

      // investor wants to be paid in euros
      // should fail because threshold to be paid in euros is 100 interests
      await shouldFail.reverting(this.interestsContract.claimInterests(true, web3.utils.utf8ToHex('eur'), { from: accounts[1] }));

      // checks investor claiming status
      await assertIsClaimingInterests(this.interestsContract, accounts[1], false);
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[1], '');

      // should pass because threshold to be paid in eth is 10 interests
      await this.interestsContract.claimInterests(true, web3.utils.utf8ToHex('eth'), { from: accounts[1] });

      // checks investor claiming status
      await assertIsClaimingInterests(this.interestsContract, accounts[1], true);
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[1], 'eth');
    });
    it('fails if investor is claiming EUR with insufficient interests', async function () {
      const interests = DECIMALS.multipliedBy(99);
      await this.interestsContract.setInterests(accounts[3], interests.toFixed());
      await assertIsClaimingInterests(this.interestsContract, accounts[3], false);
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[3], '');
      await assertInterestsOf(this.interestsContract, accounts[3], interests);
      await shouldFail.reverting(this.interestsContract.claimInterests(true, web3.utils.utf8ToHex('eur'), { from: accounts[3] }));
      await assertIsClaimingInterests(this.interestsContract, accounts[3], false);
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[3], '');
    });
    it('pass if investor is claiming EUR with sufficient interests', async function () {
      const interests = DECIMALS.multipliedBy(100);
      await this.interestsContract.setInterests(accounts[3], interests.toFixed());
      await assertIsClaimingInterests(this.interestsContract, accounts[3], false);
      await assertInterestsOf(this.interestsContract, accounts[3], interests);
      await this.interestsContract.claimInterests(true, web3.utils.utf8ToHex('eur'), { from: accounts[3] });
      await assertIsClaimingInterests(this.interestsContract, accounts[3], true);
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[3], 'eur');
    });
    it('fails if investor is claiming ETH with insufficient interests', async function () {
      const interests = DECIMALS.multipliedBy(9);
      await this.interestsContract.setInterests(accounts[3], interests);
      await assertIsClaimingInterests(this.interestsContract, accounts[3], false);
      await assertInterestsOf(this.interestsContract, accounts[3], interests);
      await shouldFail.reverting(this.interestsContract.claimInterests(true, web3.utils.utf8ToHex('eth'), { from: accounts[3] }));
      await assertIsClaimingInterests(this.interestsContract, accounts[3], false);
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[3], '');
    });
    it('pass if investor is claiming ETH with sufficient interests', async function () {
      const interests = DECIMALS.multipliedBy(10);
      await this.interestsContract.setInterests(accounts[3], interests);
      await assertIsClaimingInterests(this.interestsContract, accounts[3], false);
      await assertInterestsOf(this.interestsContract, accounts[3], interests);
      await this.interestsContract.claimInterests(true, web3.utils.utf8ToHex('eth'), { from: accounts[3] });
      await assertIsClaimingInterests(this.interestsContract, accounts[3], true);
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[3], 'eth');
    });
    it('investor wants to cancel his request', async function () {
      const interests = DECIMALS.multipliedBy(100);
      await this.interestsContract.setInterests(accounts[3], interests);
      await assertIsClaimingInterests(this.interestsContract, accounts[3], false);
      await assertInterestsOf(this.interestsContract, accounts[3], interests);
      await this.interestsContract.claimInterests(true, web3.utils.utf8ToHex('eth'), { from: accounts[3] });
      await assertIsClaimingInterests(this.interestsContract, accounts[3], true);
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[3], 'eth');
      await this.interestsContract.claimInterests(false, web3.utils.utf8ToHex('eth'), { from: accounts[3] });
      await assertIsClaimingInterests(this.interestsContract, accounts[3], false);
      await assertIsClaimingInterestsCurrency(this.interestsContract, accounts[3], '');
    });
    it('investor wants to claim in eth its midterm bonds bought on august 2014 (more than 5 years ago)', async function () {
      const claimedAmount = new BigNumber(100);
      const midHolding = 204;
      const lngHolding = 78524;
      const perHolding = 885;
      const perBalance = new BigNumber(4545);
      const midBalance = new BigNumber(414);
      const lngBalance = new BigNumber(1444);

      // Set holdings
      const tx0 = await this.interestsContract.setHoldings(accounts[1], midHolding, lngHolding, perHolding);
      const logs0 = tx0.logs;
      const retrievedMidHolding = await this.interestsContract.midtermBondInfosOf(accounts[1]);
      const retrievedLngHolding = await this.interestsContract.longtermBondInfosOf(accounts[1]);
      const retrievedPerHolding = await this.interestsContract.perpetualBondInfosOf(accounts[1]);
      assert.equal(retrievedMidHolding[1].toNumber(), midHolding);
      assert.equal(retrievedLngHolding[1].toNumber(), lngHolding);
      assert.equal(retrievedPerHolding[1].toNumber(), perHolding);

      assert.equal(logs0.length, 1);
      assert.equal(logs0[0].event, 'ModifiedHoldings');
      assert.equal(logs0[0].args.investor, accounts[1]);
      assert.equal(logs0[0].args.midHolding.toNumber(), midHolding);
      assert.equal(logs0[0].args.lngHolding.toNumber(), lngHolding);
      assert.equal(logs0[0].args.perHolding.toNumber(), perHolding);

      // Set balance
      const { logs } = await this.interestsContract.setBalances(accounts[1], midBalance.toNumber(), lngBalance.toNumber(), perBalance.toNumber());
      const retrievedMidBalance = await this.interestsContract.midtermBondInfosOf(accounts[1]);
      const retrievedLngBalance = await this.interestsContract.longtermBondInfosOf(accounts[1]);
      const retrievedPerBalance = await this.interestsContract.perpetualBondInfosOf(accounts[1]);
      assert.equal(new BigNumber(retrievedMidBalance[0]).toNumber(), midBalance.toNumber());
      assert.equal(new BigNumber(retrievedLngBalance[0]).toNumber(), lngBalance.toNumber());
      assert.equal(new BigNumber(retrievedPerBalance[0]).toNumber(), perBalance.toNumber());

      assert.equal(logs.length, 1);
      assert.equal(logs[0].event, 'ModifiedBalances');
      assert.equal(logs[0].args.investor, accounts[1]);
      assert.equal(new BigNumber(logs[0].args.midBalance.toString()).toFixed(), midBalance.toFixed());
      assert.equal(new BigNumber(logs[0].args.lngBalance.toString()).toFixed(), lngBalance.toFixed());
      assert.equal(new BigNumber(logs[0].args.perBalance.toString()).toFixed(), perBalance.toFixed());

      // Claim bond
      await this.interestsContract.claimBond(true, web3.utils.utf8ToHex('eth'), web3.utils.utf8ToHex('mid_201408'), { from: accounts[1] });
      await assertIsClaimingBonds(this.interestsContract, accounts[1], true);
      await assertIsClaimingBonds(this.interestsContract, accounts[2], false);
      await assertIsClaimingBondsCurrency(this.interestsContract, accounts[1], 'eth');
      await assertIsClaimingBondsCurrency(this.interestsContract, accounts[2], '');
      // The controllers pays back and notifies through payBonds() method
      await shouldFail.reverting(this.interestsContract.payBonds(accounts[1], claimedAmount, { from: accounts[5] }));
      await this.interestsContract.setInterestsController(accounts[5], true);
      const tx2 = await this.interestsContract.payBonds(accounts[1], claimedAmount, { from: accounts[5] });
      const logs2 = tx2.logs;

      assert.equal(logs2.length, 3);
      assert.equal(logs2[0].event, 'WillBePaidBonds');
      assert.equal(logs2[0].args.investor, accounts[1]);
      assert.equal(logs2[0].args.partitionNameInHex, ethers.utils.formatBytes32String('mid_201408'));

      assert.equal(logs2[1].event, 'ModifiedClaimingBonds');
      assert.equal(logs2[1].args.investor, accounts[1]);
      assert.equal(logs2[1].args.claiming, false);
      assert.equal(logs2[1].args.currency, ethers.utils.formatBytes32String(''));
      assert.equal(logs2[1].args.partitionNameInHex, ethers.utils.formatBytes32String(''));

      assert.equal(logs2[2].event, 'ModifiedBalances');
      assert.equal(logs2[2].args.investor, accounts[1]);
      assert.equal(new BigNumber(logs2[2].args.midBalance.toString()).toFixed(), midBalance.minus(claimedAmount).toFixed());
      assert.equal(new BigNumber(logs2[2].args.lngBalance.toString()).toFixed(), lngBalance.toFixed());
      assert.equal(new BigNumber(logs2[2].args.perBalance.toString()).toFixed(), perBalance.toFixed());

      await assertIsClaimingBonds(this.interestsContract, accounts[1], false);
      await assertIsClaimingBondsCurrency(this.interestsContract, accounts[1], '');
    });
    it('investor wants to claim in euros its longterm bonds bought on august 2009 (more than 10 years ago)', async function () {
      const claimedAmount = 100;
      const { logs } = await this.interestsContract.claimBond(true, web3.utils.utf8ToHex('eur'), web3.utils.utf8ToHex('lng_200908'), { from: accounts[1] });
      await assertIsClaimingBonds(this.interestsContract, accounts[1], true);
      await assertIsClaimingBonds(this.interestsContract, accounts[2], false);
      await assertIsClaimingBondsCurrency(this.interestsContract, accounts[1], 'eur');
      await assertIsClaimingBondsCurrency(this.interestsContract, accounts[2], '');
      assert.equal(logs.length, 1);
      assert.equal(logs[0].event, 'ModifiedClaimingBonds');
      assert.equal(logs[0].args.investor, accounts[1]);
      assert.equal(logs[0].args.claiming, true);
      assert.equal(logs[0].args.currency, ethers.utils.formatBytes32String('eur'));
      assert.equal(logs[0].args.partitionNameInHex, ethers.utils.formatBytes32String('lng_200908'));

      // The controllers pays back and notifies through payBonds() method
      await shouldFail.reverting(this.interestsContract.payBonds(accounts[1], claimedAmount, { from: accounts[5] }));
      await this.interestsContract.setInterestsController(accounts[5], true);
      await this.interestsContract.payBonds(accounts[1], claimedAmount, { from: accounts[5] });
      await assertIsClaimingBonds(this.interestsContract, accounts[1], false);
      await assertIsClaimingBondsCurrency(this.interestsContract, accounts[1], '');
    });
    it('investor wants to claim its longterm bonds bought on august 2009 (more than 10 years ago) but mispelled parameters', async function () {
      await shouldFail.reverting(this.interestsContract.claimBond(true, web3.utils.utf8ToHex('eur'), web3.utils.utf8ToHex('lmg_201408'), { from: accounts[1] }));
      await shouldFail.reverting(this.interestsContract.claimBond(true, web3.utils.utf8ToHex('eur'), web3.utils.utf8ToHex('lng_20I408'), { from: accounts[1] }));
      await shouldFail.reverting(this.interestsContract.claimBond(true, web3.utils.utf8ToHex('eir'), web3.utils.utf8ToHex('lng_201408'), { from: accounts[1] }));
      await assertIsClaimingBonds(this.interestsContract, accounts[1], false);
      await assertIsClaimingBondsCurrency(this.interestsContract, accounts[1], '');
    });
    it('investor wants to claim its longterm bonds bought on august 2019 (less than 10 years ago)', async function () {
      await shouldFail.reverting(this.interestsContract.claimBond(true, web3.utils.utf8ToHex('eur'), web3.utils.utf8ToHex('lng_201904'), { from: accounts[1] }));

      await assertIsClaimingBonds(this.interestsContract, accounts[1], false);
      await assertIsClaimingBondsCurrency(this.interestsContract, accounts[1], '');
    });
    it('investor wants to claim its midterm bonds bought on august 2019 (less than 5 years ago)', async function () {
      await shouldFail.reverting(this.interestsContract.claimBond(true, web3.utils.utf8ToHex('eur'), web3.utils.utf8ToHex('mid_201904'), { from: accounts[1] }));

      await assertIsClaimingBonds(this.interestsContract, accounts[1], false);
      await assertIsClaimingBondsCurrency(this.interestsContract, accounts[1], '');
    });
    it('investor wants to cheat by submiting a fake partition name', async function () {
      const claimedAmount = 100;
      await this.interestsContract.claimBond(true, web3.utils.utf8ToHex('eth'), web3.utils.utf8ToHex('mid_200104'), { from: accounts[1] });
      await assertIsClaimingBonds(this.interestsContract, accounts[1], true);
      await assertIsClaimingBonds(this.interestsContract, accounts[2], false);
      await assertIsClaimingBondsCurrency(this.interestsContract, accounts[1], 'eth');
      await assertIsClaimingBondsCurrency(this.interestsContract, accounts[2], '');
      // The controller HAS TO CHECK the balance of the specified partition and to use the payBonds method to clear the table
      await shouldFail.reverting(this.interestsContract.payBonds(accounts[1], claimedAmount, { from: accounts[5] }));
      await this.interestsContract.setInterestsController(accounts[5], true);
      await this.interestsContract.payBonds(accounts[1], claimedAmount, { from: accounts[5] });
      await assertIsClaimingBonds(this.interestsContract, accounts[1], false);
      await assertIsClaimingBondsCurrency(this.interestsContract, accounts[1], '');
    });
    it('owner want to set referee amount', async function () {
      const referee = accounts[4];
      const midAmount = DECIMALS.multipliedBy(100);
      const lngAmount = DECIMALS.multipliedBy(200);
      const perAmount = DECIMALS.multipliedBy(300);
      const { logs } = await this.interestsContract.setRefereeAmount(referee, midAmount.toFixed(), lngAmount.toFixed(), perAmount.toFixed());

      assert.equal(logs.length, 1);
      assert.equal(logs[0].event, 'ModifiedReferee');
      assert.equal(logs[0].args.investor, referee);
      assert.equal(new BigNumber(logs[0].args.perAmount.toString()).toFixed(), perAmount.toFixed());
      assert.equal(new BigNumber(logs[0].args.midAmount.toString()).toFixed(), midAmount.toFixed());
      assert.equal(new BigNumber(logs[0].args.lngAmount.toString()).toFixed(), lngAmount.toFixed());

      const computedRefereeBalanceMid = await this.interestsContract.midtermBondInfosOf(referee);
      assert.equal(new BigNumber(computedRefereeBalanceMid[2]).toNumber(), midAmount.toNumber());
      const computedRefereeBalanceLng = await this.interestsContract.longtermBondInfosOf(referee);
      assert.equal(new BigNumber(computedRefereeBalanceLng[2]).toNumber(), lngAmount.toNumber());
      const computedRefereeBalancePer = await this.interestsContract.perpetualBondInfosOf(referee);
      assert.equal(new BigNumber(computedRefereeBalancePer[2]).toNumber(), perAmount.toNumber());
    });
  });
  describe('when setHoldings is called', function () {
    it('set custom holding balances', async function () {
      const midHolding = 200;
      const lngHolding = 10000;
      const perHolding = 200000;
      await shouldFail.reverting(this.interestsContract.setHoldings(accounts[2], midHolding, lngHolding, perHolding, { from: accounts[5] }));
      const { logs } = await this.interestsContract.setHoldings(accounts[2], midHolding, lngHolding, perHolding);
      const retrievedMidHolding = await this.interestsContract.midtermBondInfosOf(accounts[2]);
      const retrievedLngHolding = await this.interestsContract.longtermBondInfosOf(accounts[2]);
      const retrievedPerHolding = await this.interestsContract.perpetualBondInfosOf(accounts[2]);
      assert.equal(retrievedMidHolding[1].toNumber(), midHolding);
      assert.equal(retrievedLngHolding[1].toNumber(), lngHolding);
      assert.equal(retrievedPerHolding[1].toNumber(), perHolding);

      assert.equal(logs.length, 1);
      assert.equal(logs[0].event, 'ModifiedHoldings');
      assert.equal(logs[0].args.investor, accounts[2]);
      assert.equal(logs[0].args.midHolding.toNumber(), midHolding);
      assert.equal(logs[0].args.lngHolding.toNumber(), lngHolding);
      assert.equal(logs[0].args.perHolding.toNumber(), perHolding);
    });
  });
  describe('when setBalances is called', function () {
    it('set custom balances', async function () {
      const midBalance = new BigNumber(200);
      const lngBalance = new BigNumber(10000);
      const perBalance = new BigNumber(200000);
      await shouldFail.reverting(this.interestsContract.setBalances(accounts[2], midBalance.toNumber(), lngBalance.toNumber(), perBalance.toNumber(), { from: accounts[5] }));
      const { logs } = await this.interestsContract.setBalances(accounts[2], midBalance.toNumber(), lngBalance.toNumber(), perBalance.toNumber());
      const retrievedMidBalance = await this.interestsContract.midtermBondInfosOf(accounts[2]);
      const retrievedLngBalance = await this.interestsContract.longtermBondInfosOf(accounts[2]);
      const retrievedPerBalance = await this.interestsContract.perpetualBondInfosOf(accounts[2]);
      assert.equal(new BigNumber(retrievedMidBalance[0]).toNumber(), midBalance.toNumber());
      assert.equal(new BigNumber(retrievedLngBalance[0]).toNumber(), lngBalance.toNumber());
      assert.equal(new BigNumber(retrievedPerBalance[0]).toNumber(), perBalance.toNumber());

      assert.equal(logs.length, 1);
      assert.equal(logs[0].event, 'ModifiedBalances');
      assert.equal(logs[0].args.investor, accounts[2]);
      assert.equal(new BigNumber(logs[0].args.midBalance.toString()).toFixed(), midBalance.toFixed());
      assert.equal(new BigNumber(logs[0].args.lngBalance.toString()).toFixed(), lngBalance.toFixed());
      assert.equal(new BigNumber(logs[0].args.perBalance.toString()).toFixed(), perBalance.toFixed());
    });
  });
  describe('when payBonds is called', function () {
    it('when claimedAmount bigger than current balance', async function () {
      const claimedAmount = new BigNumber(500);
      const perBalance = new BigNumber(250);
      const midBalance = new BigNumber(137);
      const lngBalance = new BigNumber(452);
      const midHolding = 19;
      const lngHolding = 57;
      const perHolding = 14;

      assert(claimedAmount.toNumber() > midBalance.toNumber());

      // Set holdings
      const { logs } = await this.interestsContract.setHoldings(accounts[2], midHolding, lngHolding, perHolding);
      const retrievedMidHolding = await this.interestsContract.midtermBondInfosOf(accounts[2]);
      const retrievedLngHolding = await this.interestsContract.longtermBondInfosOf(accounts[2]);
      const retrievedPerHolding = await this.interestsContract.perpetualBondInfosOf(accounts[2]);
      assert.equal(retrievedMidHolding[1].toNumber(), midHolding);
      assert.equal(retrievedLngHolding[1].toNumber(), lngHolding);
      assert.equal(retrievedPerHolding[1].toNumber(), perHolding);

      assert.equal(logs.length, 1);
      assert.equal(logs[0].event, 'ModifiedHoldings');
      assert.equal(logs[0].args.investor, accounts[2]);
      assert.equal(logs[0].args.midHolding.toNumber(), midHolding);
      assert.equal(logs[0].args.lngHolding.toNumber(), lngHolding);
      assert.equal(logs[0].args.perHolding.toNumber(), perHolding);

      // Set balance
      const tx1 = await this.interestsContract.setBalances(accounts[2], midBalance.toNumber(), lngBalance.toNumber(), perBalance.toNumber());
      const logs2 = tx1.logs;
      const retrievedMidBalance = await this.interestsContract.midtermBondInfosOf(accounts[2]);
      const retrievedLngBalance = await this.interestsContract.longtermBondInfosOf(accounts[2]);
      const retrievedPerBalance = await this.interestsContract.perpetualBondInfosOf(accounts[2]);
      assert.equal(new BigNumber(retrievedMidBalance[0]).toNumber(), midBalance.toNumber());
      assert.equal(new BigNumber(retrievedLngBalance[0]).toNumber(), lngBalance.toNumber());
      assert.equal(new BigNumber(retrievedPerBalance[0]).toNumber(), perBalance.toNumber());

      assert.equal(logs2.length, 1);
      assert.equal(logs2[0].event, 'ModifiedBalances');
      assert.equal(logs2[0].args.investor, accounts[2]);
      assert.equal(new BigNumber(logs2[0].args.midBalance.toString()).toFixed(), midBalance.toFixed());
      assert.equal(new BigNumber(logs2[0].args.lngBalance.toString()).toFixed(), lngBalance.toFixed());
      assert.equal(new BigNumber(logs2[0].args.perBalance.toString()).toFixed(), perBalance.toFixed());

      // Pay bond
      await shouldFail.reverting(this.interestsContract.payBonds(accounts[2], claimedAmount, { from: accounts[5] }));
      await this.interestsContract.setInterestsController(accounts[5], true);
      await shouldFail.reverting(this.interestsContract.payBonds(accounts[2], claimedAmount, { from: accounts[5] }));
      await this.interestsContract.claimBond(true, web3.utils.utf8ToHex('eth'), web3.utils.utf8ToHex('mid_200104'), { from: accounts[2] });
      await assertIsClaimingBonds(this.interestsContract, accounts[2], true);

      const tx2 = await this.interestsContract.payBonds(accounts[2], claimedAmount, { from: accounts[5] });
      const logs3 = tx2.logs;
      const retrievedMidBalance2 = await this.interestsContract.midtermBondInfosOf(accounts[2]);
      const retrievedLngBalance2 = await this.interestsContract.longtermBondInfosOf(accounts[2]);
      const retrievedPerBalance2 = await this.interestsContract.perpetualBondInfosOf(accounts[2]);
      assert.equal(new BigNumber(retrievedMidBalance2[0]).toNumber(), 0);
      assert.equal(new BigNumber(retrievedLngBalance2[0]).toNumber(), lngBalance.toNumber());
      assert.equal(new BigNumber(retrievedPerBalance2[0]).toNumber(), perBalance.toNumber());

      // Check current holding
      assert.equal(retrievedMidBalance2[1].toNumber(), 0);
      assert.equal(retrievedLngBalance2[1].toNumber(), lngHolding);
      assert.equal(retrievedPerBalance2[1].toNumber(), perHolding);

      assert.equal(logs3.length, 5);

      assert.equal(logs3[0].event, 'ModifiedHoldingsAndBalanceError');
      assert.equal(logs3[0].args.investor, accounts[2]);
      assert.equal(logs3[0].args.partitionNameInHex, ethers.utils.formatBytes32String('mid_200104'));
      assert.equal(logs3[0].args.holding.toNumber(), midHolding);
      assert.equal(new BigNumber(logs3[0].args.balance.toString()).toFixed(), midBalance.toFixed());

      assert.equal(logs3[1].event, 'WillBePaidBonds');
      assert.equal(logs3[1].args.investor, accounts[2]);
      assert.equal(logs3[1].args.partitionNameInHex, ethers.utils.formatBytes32String('mid_200104'));

      assert.equal(logs3[2].event, 'ModifiedClaimingBonds');
      assert.equal(logs3[2].args.investor, accounts[2]);
      assert.equal(logs3[2].args.claiming, false);
      assert.equal(logs3[2].args.currency, ethers.utils.formatBytes32String(''));
      assert.equal(logs3[2].args.partitionNameInHex, ethers.utils.formatBytes32String(''));

      assert.equal(logs3[3].event, 'ModifiedHoldings');
      assert.equal(logs3[3].args.investor, accounts[2]);
      assert.equal(logs3[3].args.midHolding.toNumber(), 0);
      assert.equal(logs3[3].args.lngHolding.toNumber(), lngHolding);
      assert.equal(logs3[3].args.perHolding.toNumber(), perHolding);

      assert.equal(logs3[4].event, 'ModifiedBalances');
      assert.equal(logs3[4].args.investor, accounts[2]);
      assert.equal(new BigNumber(logs3[4].args.midBalance.toString()).toFixed(), 0);
      assert.equal(new BigNumber(logs3[4].args.lngBalance.toString()).toFixed(), lngBalance.toFixed());
      assert.equal(new BigNumber(logs3[4].args.perBalance.toString()).toFixed(), perBalance.toFixed());
    });
    it('when claimedAmount lower than current balance', async function () {
      const claimedAmount = new BigNumber(300);
      const perBalance = new BigNumber(124);
      const midBalance = new BigNumber(854);
      const lngBalance = new BigNumber(400);
      const midHolding = 12;
      const lngHolding = 14;
      const perHolding = 12;

      assert(claimedAmount.toNumber() < lngBalance.toNumber());

      // Set holdings
      const { logs } = await this.interestsContract.setHoldings(accounts[2], midHolding, lngHolding, perHolding);
      const retrievedMidHolding = await this.interestsContract.midtermBondInfosOf(accounts[2]);
      const retrievedLngHolding = await this.interestsContract.longtermBondInfosOf(accounts[2]);
      const retrievedPerHolding = await this.interestsContract.perpetualBondInfosOf(accounts[2]);
      assert.equal(retrievedMidHolding[1].toNumber(), midHolding);
      assert.equal(retrievedLngHolding[1].toNumber(), lngHolding);
      assert.equal(retrievedPerHolding[1].toNumber(), perHolding);

      assert.equal(logs.length, 1);
      assert.equal(logs[0].event, 'ModifiedHoldings');
      assert.equal(logs[0].args.investor, accounts[2]);
      assert.equal(logs[0].args.midHolding.toNumber(), midHolding);
      assert.equal(logs[0].args.lngHolding.toNumber(), lngHolding);
      assert.equal(logs[0].args.perHolding.toNumber(), perHolding);

      // Set balance
      const tx1 = await this.interestsContract.setBalances(accounts[2], midBalance.toNumber(), lngBalance.toNumber(), perBalance.toNumber());
      const logs2 = tx1.logs;
      const retrievedMidBalance = await this.interestsContract.midtermBondInfosOf(accounts[2]);
      const retrievedLngBalance = await this.interestsContract.longtermBondInfosOf(accounts[2]);
      const retrievedPerBalance = await this.interestsContract.perpetualBondInfosOf(accounts[2]);
      assert.equal(new BigNumber(retrievedMidBalance[0]).toNumber(), midBalance.toNumber());
      assert.equal(new BigNumber(retrievedLngBalance[0]).toNumber(), lngBalance.toNumber());
      assert.equal(new BigNumber(retrievedPerBalance[0]).toNumber(), perBalance.toNumber());

      assert.equal(logs2.length, 1);
      assert.equal(logs2[0].event, 'ModifiedBalances');
      assert.equal(logs2[0].args.investor, accounts[2]);
      assert.equal(new BigNumber(logs2[0].args.midBalance.toString()).toFixed(), midBalance.toFixed());
      assert.equal(new BigNumber(logs2[0].args.lngBalance.toString()).toFixed(), lngBalance.toFixed());
      assert.equal(new BigNumber(logs2[0].args.perBalance.toString()).toFixed(), perBalance.toFixed());

      // Pay bond
      await shouldFail.reverting(this.interestsContract.payBonds(accounts[2], claimedAmount, { from: accounts[5] }));
      await this.interestsContract.setInterestsController(accounts[5], true);
      await shouldFail.reverting(this.interestsContract.payBonds(accounts[2], claimedAmount, { from: accounts[5] }));
      await this.interestsContract.claimBond(true, web3.utils.utf8ToHex('eth'), web3.utils.utf8ToHex('lng_200104'), { from: accounts[2] });
      await assertIsClaimingBonds(this.interestsContract, accounts[2], true);

      const tx2 = await this.interestsContract.payBonds(accounts[2], claimedAmount, { from: accounts[5] });
      const logs3 = tx2.logs;
      const retrievedMidBalance2 = await this.interestsContract.midtermBondInfosOf(accounts[2]);
      const retrievedLngBalance2 = await this.interestsContract.longtermBondInfosOf(accounts[2]);
      const retrievedPerBalance2 = await this.interestsContract.perpetualBondInfosOf(accounts[2]);
      assert.equal(new BigNumber(retrievedMidBalance2[0]).toNumber(), midBalance.toNumber());
      assert.equal(new BigNumber(retrievedLngBalance2[0]).toNumber(), lngBalance.toNumber() - claimedAmount.toNumber());
      assert.equal(new BigNumber(retrievedPerBalance2[0]).toNumber(), perBalance.toNumber());

      // Check current holding
      assert.equal(retrievedMidBalance[1].toNumber(), midHolding);
      assert.equal(retrievedLngBalance[1].toNumber(), lngHolding);
      assert.equal(retrievedPerBalance[1].toNumber(), perHolding);

      assert.equal(logs3.length, 3);
      assert.equal(logs3[0].event, 'WillBePaidBonds');
      assert.equal(logs3[0].args.investor, accounts[2]);
      assert.equal(logs3[0].args.partitionNameInHex, ethers.utils.formatBytes32String('lng_200104'));

      assert.equal(logs3[1].event, 'ModifiedClaimingBonds');
      assert.equal(logs3[1].args.investor, accounts[2]);
      assert.equal(logs3[1].args.claiming, false);
      assert.equal(logs3[1].args.currency, ethers.utils.formatBytes32String(''));
      assert.equal(logs3[1].args.partitionNameInHex, ethers.utils.formatBytes32String(''));

      assert.equal(logs3[2].event, 'ModifiedBalances');
      assert.equal(logs3[2].args.investor, accounts[2]);
      assert.equal(new BigNumber(logs3[2].args.midBalance.toString()).toFixed(), midBalance.toFixed());
      assert.equal(new BigNumber(logs3[2].args.lngBalance.toString()).toFixed(), lngBalance.minus(claimedAmount).toFixed());
      assert.equal(new BigNumber(logs3[2].args.perBalance.toString()).toFixed(), perBalance.toFixed());
    });
    it('when claimedAmount == current balance, it should reset currentHolding', async function () {
      const claimedAmount = new BigNumber(150);
      const perBalance = new BigNumber(124);
      const midBalance = new BigNumber(75457);
      const lngBalance = new BigNumber(150);
      const midHolding = 1;
      const lngHolding = 2;
      const perHolding = 3;

      assert.equal(claimedAmount.toString(), lngBalance.toString());

      // Set holdings
      const { logs } = await this.interestsContract.setHoldings(accounts[2], midHolding, lngHolding, perHolding);
      const retrievedMidHolding = await this.interestsContract.midtermBondInfosOf(accounts[2]);
      const retrievedLngHolding = await this.interestsContract.longtermBondInfosOf(accounts[2]);
      const retrievedPerHolding = await this.interestsContract.perpetualBondInfosOf(accounts[2]);
      assert.equal(retrievedMidHolding[1].toNumber(), midHolding);
      assert.equal(retrievedLngHolding[1].toNumber(), lngHolding);
      assert.equal(retrievedPerHolding[1].toNumber(), perHolding);

      assert.equal(logs.length, 1);
      assert.equal(logs[0].event, 'ModifiedHoldings');
      assert.equal(logs[0].args.investor, accounts[2]);
      assert.equal(logs[0].args.midHolding.toNumber(), midHolding);
      assert.equal(logs[0].args.lngHolding.toNumber(), lngHolding);
      assert.equal(logs[0].args.perHolding.toNumber(), perHolding);

      // Set Balances
      const tx0 = await this.interestsContract.setBalances(accounts[2], midBalance.toNumber(), lngBalance.toNumber(), perBalance.toNumber());
      const logs2 = tx0.logs;
      const retrievedMidBalance = await this.interestsContract.midtermBondInfosOf(accounts[2]);
      const retrievedLngBalance = await this.interestsContract.longtermBondInfosOf(accounts[2]);
      const retrievedPerBalance = await this.interestsContract.perpetualBondInfosOf(accounts[2]);
      assert.equal(new BigNumber(retrievedMidBalance[0]).toNumber(), midBalance.toNumber());
      assert.equal(new BigNumber(retrievedLngBalance[0]).toNumber(), lngBalance.toNumber());
      assert.equal(new BigNumber(retrievedPerBalance[0]).toNumber(), perBalance.toNumber());

      assert.equal(logs2.length, 1);
      assert.equal(logs2[0].event, 'ModifiedBalances');
      assert.equal(logs2[0].args.investor, accounts[2]);
      assert.equal(new BigNumber(logs2[0].args.midBalance.toString()).toFixed(), midBalance.toFixed());
      assert.equal(new BigNumber(logs2[0].args.lngBalance.toString()).toFixed(), lngBalance.toFixed());
      assert.equal(new BigNumber(logs2[0].args.perBalance.toString()).toFixed(), perBalance.toFixed());

      // Set Claiming
      await assertIsClaimingBonds(this.interestsContract, accounts[2], false);
      await this.interestsContract.claimBond(true, web3.utils.utf8ToHex('eth'), web3.utils.utf8ToHex('lng_200104'), { from: accounts[2] });
      await assertIsClaimingBonds(this.interestsContract, accounts[2], true);

      // Pay bonds
      await this.interestsContract.setInterestsController(accounts[5], true);
      const tx1 = await this.interestsContract.payBonds(accounts[2], claimedAmount, { from: accounts[5] });
      const logs3 = tx1.logs;
      const retrievedMidBalance2 = await this.interestsContract.midtermBondInfosOf(accounts[2]);
      const retrievedLngBalance2 = await this.interestsContract.longtermBondInfosOf(accounts[2]);
      const retrievedPerBalance2 = await this.interestsContract.perpetualBondInfosOf(accounts[2]);

      // Check current balance
      assert.equal(new BigNumber(retrievedMidBalance2[0]).toNumber(), midBalance.toNumber());
      assert.equal(new BigNumber(retrievedLngBalance2[0]).toNumber(), 0);
      assert.equal(new BigNumber(retrievedPerBalance2[0]).toNumber(), perBalance.toNumber());

      // Check current holding
      assert.equal(retrievedMidBalance2[1].toNumber(), midHolding);
      assert.equal(retrievedLngBalance2[1].toNumber(), 0);
      assert.equal(retrievedPerBalance2[1].toNumber(), perHolding);

      assert.equal(logs3.length, 4);
      assert.equal(logs3[0].event, 'WillBePaidBonds');
      assert.equal(logs3[0].args.investor, accounts[2]);
      assert.equal(logs3[0].args.partitionNameInHex, ethers.utils.formatBytes32String('lng_200104'));

      assert.equal(logs3[1].event, 'ModifiedClaimingBonds');
      assert.equal(logs3[1].args.investor, accounts[2]);
      assert.equal(logs3[1].args.claiming, false);
      assert.equal(logs3[1].args.currency, ethers.utils.formatBytes32String(''));
      assert.equal(logs3[1].args.partitionNameInHex, ethers.utils.formatBytes32String(''));

      assert.equal(logs3[2].event, 'ModifiedHoldings');
      assert.equal(logs3[2].args.investor, accounts[2]);
      assert.equal(logs3[2].args.midHolding.toNumber(), midHolding);
      assert.equal(logs3[2].args.lngHolding.toNumber(), 0);
      assert.equal(logs3[2].args.perHolding.toNumber(), perHolding);

      assert.equal(logs3[3].event, 'ModifiedBalances');
      assert.equal(logs3[3].args.investor, accounts[2]);
      assert.equal(new BigNumber(logs3[3].args.midBalance.toString()).toFixed(), midBalance.toFixed());
      assert.equal(new BigNumber(logs3[3].args.lngBalance.toString()).toFixed(), 0);
      assert.equal(new BigNumber(logs3[3].args.perBalance.toString()).toFixed(), perBalance.toFixed());
    });
  });
});
