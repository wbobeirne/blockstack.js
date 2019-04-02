
import bitcoinjs from 'bitcoinjs-lib'
import { hexStringToECPair, ecPairToAddress } from '../utils'

/** @ignore */
export interface TransactionSigner {
  /**
   * @returns version number of the signer, currently, should always be 1
   * @private
   * @ignore
   */
  signerVersion(): number;
  /**
   * @returns a string representing the transaction signer's address
   * (usually Base58 check encoding)
   * @private
   * @ignore
   */
  getAddress(): Promise<string>;
  /**
   * Signs a transaction input
   * @param transaction - the transaction to sign
   * @param inputIndex - the input on the transaction to sign
   * @private
   * @ignore
   */
  signTransaction(transaction: bitcoinjs.TransactionBuilder, inputIndex: number): Promise<void>;
}

/**
 * Class representing a transaction signer for pubkeyhash addresses
 * (a.k.a. single-sig addresses)
 * @private
 * @ignore
 */
export class PubkeyHashSigner implements TransactionSigner {
  ecPair: bitcoinjs.ECPair

  constructor(ecPair: bitcoinjs.ECPair) {
    this.ecPair = ecPair
  }

  static fromHexString(keyHex: string) {
    return new PubkeyHashSigner(hexStringToECPair(keyHex))
  }

  signerVersion(): number {
    return 1
  }

  getAddress(): Promise<string> {
    return Promise.resolve()
      .then(() => ecPairToAddress(this.ecPair))
  }

  signTransaction(transaction: bitcoinjs.TransactionBuilder, inputIndex: number): Promise<void> {
    return Promise.resolve()
      .then(() => {
        transaction.sign(inputIndex, this.ecPair)
      })
  }
}
