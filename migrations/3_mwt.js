const MWTTOKEN = artifacts.require('./MWT.sol');
const MWTINTERESTS = artifacts.require('./minterests.sol');

// Account allowed to generate certificates or to bypass certificate check
const CERTIFICATE_SIGNER = '0x590694309E2F2C6B3086396CFa7d29A228Dc0268';

// controller is a global operator
// represent a global operator
const controller = '0x862373f3EbdB11ad42b852016aE6f06fc2BfEFDd';

// The only initial partition
const partitionPerpetual = '0x7065725f30303030303000000000000000000000000000000000000000000000'; // per_000000 in hex
const partitions = [partitionPerpetual];

async function deployAll (deployer, network) {
  await deployer.deploy(MWTTOKEN, 'MontessoriToken', 'MWT', 1, [controller], CERTIFICATE_SIGNER, partitions);
  await deployer.deploy(MWTINTERESTS);
}

module.exports = function (deployer, network, accounts) {
  deployer.then(async () => {
    await deployAll(deployer, network);
  }).catch(e => { console.log(e); });
};
