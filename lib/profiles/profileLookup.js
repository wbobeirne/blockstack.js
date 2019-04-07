"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const profileZoneFiles_1 = require("./profileZoneFiles");
const config_1 = require("../config");
/**
 * Look up a user profile by blockstack ID
 *
 * @param {string} username - The Blockstack ID of the profile to look up
 * @param {string} [zoneFileLookupURL=null] - The URL
 * to use for zonefile lookup. If falsey, lookupProfile will use the
 * blockstack.js getNameInfo function.
 * @returns {Promise} that resolves to a profile object
 */
function lookupProfile(username, zoneFileLookupURL = null) {
    if (!username) {
        return Promise.reject();
    }
    let lookupPromise;
    if (zoneFileLookupURL) {
        const url = `${zoneFileLookupURL.replace(/\/$/, '')}/${username}`;
        lookupPromise = fetch(url)
            .then(response => response.json());
    }
    else {
        lookupPromise = config_1.config.network.getNameInfo(username);
    }
    return lookupPromise
        .then((responseJSON) => {
        if (responseJSON.hasOwnProperty('zonefile')
            && responseJSON.hasOwnProperty('address')) {
            return profileZoneFiles_1.resolveZoneFileToProfile(responseJSON.zonefile, responseJSON.address);
        }
        else {
            throw new Error('Invalid zonefile lookup response: did not contain `address`'
                + ' or `zonefile` field');
        }
    });
}
exports.lookupProfile = lookupProfile;
//# sourceMappingURL=profileLookup.js.map