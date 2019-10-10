require('dotenv').config();
require('babel-register');
require('babel-polyfill');

const HDWalletProvider = require('truffle-hdwallet-provider');
const authInfo = require('./auth.json');

const providerWithMnemonic = (mnemonic, rpcEndpoint) => () =>
  new HDWalletProvider(mnemonic, rpcEndpoint);

const infuraProviderRopsten = network => providerWithMnemonic(
  authInfo.ropsten.mnemonic || '',
  `${authInfo.ropsten.node}/${authInfo.ropsten.key}`
);

const infuraProviderGoerli = network => providerWithMnemonic(
  authInfo.goerli.mnemonic || '',
  `${authInfo.goerli.node}/${authInfo.goerli.key}`
);

const infuraProviderKovan = network => providerWithMnemonic(
  authInfo.kovan.mnemonic || '',
  `${authInfo.kovan.node}/${authInfo.kovan.key}`
);

const infuraProviderMainnet = network => providerWithMnemonic(
  authInfo.mainnet.mnemonic || '',
  `${authInfo.mainnet.node}/${authInfo.mainnet.key}`
);

const ropstenProvider = authInfo.ropsten.solidityCoverage
  ? undefined
  : infuraProviderRopsten('ropsten');

const goerliProvider = authInfo.goerli.solidityCoverage
  ? undefined
  : infuraProviderGoerli('goerli');

const kovanProvider = authInfo.kovan.solidityCoverage
  ? undefined
  : infuraProviderKovan('kovan');

const mainnetProvider = authInfo.mainnet.solidityCoverage
  ? undefined
  : infuraProviderMainnet('mainnet');

module.exports = {
  networks: {
    development: {
      host: 'localhost',
      port: 8545,
      network_id: '*', // eslint-disable-line camelcase
      gasPrice: 0x01,
    },
    ropsten: {
      provider: ropstenProvider,
      network_id: 3, // eslint-disable-line camelcase
      gas: 6712388, // default is 4712388
      gasPrice: 5000000000, // default is 100000000000 (@see https://www.trufflesuite.com/docs/truffle/reference/configuration)
    },
    goerli: {
      provider: goerliProvider,
      network_id: 5, // eslint-disable-line camelcase
      gas: 6712388, // default is 4712388
      gasPrice: 5000000000, // default is 100000000000 (@see https://www.trufflesuite.com/docs/truffle/reference/configuration)
    },
    kovan: {
      provider: kovanProvider,
      network_id: 42, // eslint-disable-line camelcase
      gas: 6712388, // default is 4712388
      gasPrice: 5000000000, // default is 100000000000 (@see https://www.trufflesuite.com/docs/truffle/reference/configuration)
    },
    mainnet: {
      provider: mainnetProvider,
      network_id: 1, // eslint-disable-line camelcase
      gas: 6712388, // default is 4712388
      gasPrice: 4000000000, // default is 100000000000 (@see https://www.trufflesuite.com/docs/truffle/reference/configuration)
    },
    coverage: {
      host: 'localhost',
      network_id: '*', // eslint-disable-line camelcase
      port: 8555,
      gas: 0xfffffffffff,
      gasPrice: 0x01,
    },
    ganache: {
      host: 'localhost',
      port: 7545,
      network_id: '*', // eslint-disable-line camelcase
    },
    private: {
      /*
        starting from address 0 of wallet with 10 addresses
        @see https://github.com/trufflesuite/truffle-hdwallet-provider/blob/master/index.js
      */
      provider: () => new HDWalletProvider(authInfo.private.mnemonic, authInfo.private.node, 0, 10),
      // eslint-disable-next-line
      network_id: '*', // Any network (default: none)
    },
    dotEnvNetwork: {
      provider: providerWithMnemonic(
        process.env.MNEMONIC,
        process.env.RPC_ENDPOINT
      ),
      network_id: parseInt(process.env.NETWORK_ID) || '*', // eslint-disable-line camelcase
    },
  },
  compilers: {
    solc: {
      version: '0.5.12-alpine',
      docker: true,
      settings: {
        optimizer: {
          enabled: true, // Default: false
          runs: 0, // Default: 200 | consensys default 0
        },
      },
    },
  },
};
