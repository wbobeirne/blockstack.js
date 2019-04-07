"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
// @ts-ignore: Could not find a declaration file for module
const schema_inspector_1 = __importDefault(require("schema-inspector"));
const profileTokens_1 = require("./profileTokens");
const profileProofs_1 = require("./profileProofs");
const profileZoneFiles_1 = require("./profileZoneFiles");
const schemaDefinition = {
    type: 'object',
    properties: {
        '@context': { type: 'string', optional: true },
        '@type': { type: 'string' }
    }
};
class Profile {
    constructor(profile = {}) {
        this._profile = Object.assign({}, {
            '@context': 'http://schema.org/'
        }, profile);
    }
    toJSON() {
        return Object.assign({}, this._profile);
    }
    toToken(privateKey) {
        return profileTokens_1.signProfileToken(this.toJSON(), privateKey);
    }
    static validateSchema(profile, strict = false) {
        schemaDefinition.strict = strict;
        return schema_inspector_1.default.validate(schemaDefinition, profile);
    }
    static fromToken(token, publicKeyOrAddress = null) {
        const profile = profileTokens_1.extractProfile(token, publicKeyOrAddress);
        return new Profile(profile);
    }
    static makeZoneFile(domainName, tokenFileURL) {
        return profileZoneFiles_1.makeProfileZoneFile(domainName, tokenFileURL);
    }
    static validateProofs(domainName) {
        return profileProofs_1.validateProofs(new Profile().toJSON(), domainName);
    }
}
exports.Profile = Profile;
//# sourceMappingURL=profile.js.map