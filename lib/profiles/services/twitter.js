"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const cheerio_1 = __importDefault(require("cheerio"));
const service_1 = require("./service");
class Twitter extends service_1.Service {
    static getBaseUrls() {
        const baseUrls = [
            'https://twitter.com/',
            'http://twitter.com/',
            'twitter.com/'
        ];
        return baseUrls;
    }
    static normalizeUrl(proof) {
        return '';
    }
    static getProofStatement(searchText) {
        const $ = cheerio_1.default.load(searchText);
        const statement = $('meta[property="og:description"]').attr('content');
        if (statement !== undefined) {
            return statement.trim().replace('“', '').replace('”', '');
        }
        else {
            return '';
        }
    }
}
exports.Twitter = Twitter;
//# sourceMappingURL=twitter.js.map