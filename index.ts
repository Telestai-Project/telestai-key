import {
  mnemonicToSeedSync,
  generateMnemonic as bip39GenerateMnemonic,
  validateMnemonic,
  entropyToMnemonic as bip39EntropyToMnemonic,
  wordlists,
} from "bip39";
import { BIP32Factory, BIP32Interface } from "bip32";
import * as ecc from "tiny-secp256k1";
import { Buffer } from "buffer";
const CoinKey = require("coinkey");

// Initialize bip32 with tiny-secp256k1
const bip32 = BIP32Factory(ecc);

// Define IAddressObject type
export interface IAddressObject {
  address: string;
  path: string;
  privateKey: string;
  WIF: string;
}

// Define Network type
export type Network = "tls";

// Define network details
function getNetwork(name: Network) {
  if (name !== "tls") {
    throw new Error("network must be 'tls'");
  }

  return {
    bip32: {
      private: 0x0488ade4,
      public: 0x0488b21e,
    },
    bip44: 10117,
    private: 0x80,
    public: 0x42,
    scripthash: 0x7f,
    wif: 0x80, // Added `wif` property
  };
}

/**
 * @param network
 * @returns the coin type for the network (blockchain)
 */
export function getCoinType(network: Network) {
  const chain = getNetwork(network);
  return chain.bip44;
}

/**
 * @param network - should have value "tls"
 * @param mnemonic - your mnemonic
 * @param account - accounts in BIP44 starts from 0, 0 is the default account
 * @param position - starts from 0
 */
export function getAddressPair(
  network: Network,
  mnemonic: string,
  account: number,
  position: number
) {
  const hdKey = getHDKey(network, mnemonic);
  const coinType = getCoinType(network);

  // Syntax of BIP44
  // m / purpose' / coin_type' / account' / change / address_index
  const externalPath = `m/44'/${coinType}'/${account}'/0/${position}`;
  const externalAddress = getAddressByPath(network, hdKey, externalPath);

  const internalPath = `m/44'/${coinType}'/${account}'/1/${position}`;
  const internalAddress = getAddressByPath(network, hdKey, internalPath);

  return {
    internal: internalAddress,
    external: externalAddress,
    position,
  };
}

export function getHDKey(network: Network, mnemonic: string): BIP32Interface {
  const chain = getNetwork(network);
  const seed = mnemonicToSeedSync(mnemonic);
  return bip32.fromSeed(seed, chain);
}

export function getAddressByPath(
  network: Network,
  hdKey: BIP32Interface,
  path: string
): IAddressObject {
  const chain = getNetwork(network);
  const derived = hdKey.derivePath(path);

  if (!derived.privateKey) {
    throw new Error("Private key derivation failed");
  }

  const privateKeyBuffer = Buffer.from(derived.privateKey); // Explicit Buffer conversion
  const ck = new CoinKey(privateKeyBuffer, chain);

  return {
    address: ck.publicAddress,
    path: path,
    privateKey: privateKeyBuffer.toString("hex"), // Hex string
    WIF: ck.privateWif,
  };
}

export function generateMnemonic(): string {
  return bip39GenerateMnemonic();
}

export function isMnemonicValid(mnemonic: string): boolean {
  const allWordlists = Object.values(wordlists);

  for (const wordlist of allWordlists) {
    if (validateMnemonic(mnemonic, wordlist as string[])) {
      return true;
    }
  }
  return false;
}

/**
 * @param privateKeyWIF
 * @param network  should be "tls"
 * @returns object {address, privateKey (hex), WIF, path}
 */
export function getAddressByWIF(network: Network, privateKeyWIF: string): IAddressObject {
  const coinKey = CoinKey.fromWif(privateKeyWIF);
  coinKey.versions = getNetwork(network);

  return {
    address: coinKey.publicAddress,
    privateKey: Buffer.from(coinKey.privateKey).toString("hex"), // Hex string
    WIF: coinKey.privateWif,
    path: "N/A", // Path is not applicable for WIF-based addresses
  };
}

export const entropyToMnemonic = bip39EntropyToMnemonic;

export function generateAddressObject(network: Network = "tls"): IAddressObject & { mnemonic: string; network: Network } {
  const mnemonic = generateMnemonic();
  const account = 0;
  const position = 0;
  const addressPair = getAddressPair(network, mnemonic, account, position);

  return {
    ...addressPair.external,
    mnemonic,
    network, // Include the network property
  };
}

export function generateAddress(network: Network = "tls") {
  return generateAddressObject(network);
}


export default {
  entropyToMnemonic,
  generateAddress,
  generateMnemonic,
  getAddressByPath,
  getAddressByWIF,
  getAddressPair,
  getCoinType,
  getHDKey,
  isMnemonicValid,
};
