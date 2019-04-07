"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const cheerio_1 = __importDefault(require("cheerio"));
const service_1 = require("./service");
class HackerNews extends service_1.Service {
    static getBaseUrls() {
        const baseUrls = [
            'https://news.ycombinator.com/user?id=',
            'http://news.ycombinator.com/user?id=',
            'news.ycombinator.com/user?id='
        ];
        return baseUrls;
    }
    static getProofUrl(proof) {
        const baseUrls = this.getBaseUrls();
        const proofUrl = super.prefixScheme(proof.proof_url);
        for (let i = 0; i < baseUrls.length; i++) {
            if (proofUrl === `${baseUrls[i]}${proof.identifier}`) {
                return proofUrl;
            }
        }
        throw new Error(`Proof url ${proof.proof_url} is not valid for service ${proof.service}`);
    }
    static normalizeUrl(proof) {
        return '';
    }
    static getProofStatement(searchText) {
        const $ = cheerio_1.default.load(searchText);
        const tables = $('#hnmain').children().find('table');
        let statement = '';
        if (tables.length > 0) {
            tables.each((tableIndex, table) => {
                const rows = $(table).find('tr');
                if (rows.length > 0) {
                    rows.each((idx, row) => {
                        const heading = $(row).find('td')
                            .first()
                            .text()
                            .trim();
                        if (heading === 'about:') {
                            statement = $(row).find('td')
                                .last()
                                .text()
                                .trim();
                        }
                    });
                }
            });
        }
        return statement;
    }
}
exports.HackerNews = HackerNews;
//# sourceMappingURL=hackerNews.js.map