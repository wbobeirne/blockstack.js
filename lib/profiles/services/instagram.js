"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const cheerio_1 = __importDefault(require("cheerio"));
const service_1 = require("./service");
class Instagram extends service_1.Service {
    static getBaseUrls() {
        const baseUrls = ['https://www.instagram.com/', 'https://instagram.com/'];
        return baseUrls;
    }
    static getProofUrl(proof) {
        const baseUrls = this.getBaseUrls();
        const normalizedProofUrl = this.normalizeUrl(proof);
        for (let i = 0; i < baseUrls.length; i++) {
            if (normalizedProofUrl.startsWith(`${baseUrls[i]}`)) {
                return normalizedProofUrl;
            }
        }
        throw new Error(`Proof url ${proof.proof_url} is not valid for service ${proof.service}`);
    }
    static normalizeUrl(proof) {
        let proofUrl = proof.proof_url;
        proofUrl = super.prefixScheme(proofUrl);
        if (proofUrl.startsWith('https://instagram.com')) {
            const tokens = proofUrl.split('https://instagram.com');
            proofUrl = `https://www.instagram.com${tokens[1]}`;
        }
        return proofUrl;
    }
    static shouldValidateIdentityInBody() {
        return true;
    }
    static getProofIdentity(searchText) {
        const $ = cheerio_1.default.load(searchText);
        const username = $('meta[property="og:description"]').attr('content');
        if (username !== undefined && username.split(':').length > 1) {
            return username.split(':')[0].match(/(@\w+)/)[0].substr(1);
        }
        else {
            return '';
        }
    }
    static getProofStatement(searchText) {
        const $ = cheerio_1.default.load(searchText);
        const statement = $('meta[property="og:description"]')
            .attr('content');
        if (statement !== undefined && statement.split(':').length > 1) {
            return statement.split(':')[1].trim().replace('“', '').replace('”', '');
        }
        else {
            return '';
        }
    }
}
exports.Instagram = Instagram;
//# sourceMappingURL=instagram.js.map