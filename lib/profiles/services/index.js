"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const facebook_1 = require("./facebook");
const github_1 = require("./github");
const twitter_1 = require("./twitter");
const instagram_1 = require("./instagram");
const hackerNews_1 = require("./hackerNews");
const linkedIn_1 = require("./linkedIn");
exports.profileServices = {
    facebook: facebook_1.Facebook,
    github: github_1.Github,
    twitter: twitter_1.Twitter,
    instagram: instagram_1.Instagram,
    hackerNews: hackerNews_1.HackerNews,
    linkedIn: linkedIn_1.LinkedIn
};
var serviceUtils_1 = require("./serviceUtils");
exports.containsValidProofStatement = serviceUtils_1.containsValidProofStatement;
exports.containsValidAddressProofStatement = serviceUtils_1.containsValidAddressProofStatement;
//# sourceMappingURL=index.js.map