"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const utils_1 = require("../utils");
/**
 * Class representing a transaction signer for pubkeyhash addresses
 * (a.k.a. single-sig addresses)
 * @private
 */
class PubkeyHashSigner {
    constructor(ecPair) {
        this.ecPair = ecPair;
    }
    static fromHexString(keyHex) {
        return new PubkeyHashSigner(utils_1.hexStringToECPair(keyHex));
    }
    signerVersion() {
        return 1;
    }
    getAddress() {
        return Promise.resolve()
            .then(() => utils_1.ecPairToAddress(this.ecPair));
    }
    signTransaction(transaction, inputIndex) {
        return Promise.resolve()
            .then(() => {
            transaction.sign(inputIndex, this.ecPair);
        });
    }
}
exports.PubkeyHashSigner = PubkeyHashSigner;
//# sourceMappingURL=signers.js.map