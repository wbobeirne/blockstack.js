"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
// @ts-ignore: Could not find a declaration file for module
const zone_file_1 = require("zone-file");
const person_1 = require("./person");
const profileZoneFiles_1 = require("../profileZoneFiles");
const profileTokens_1 = require("../profileTokens");
function resolveZoneFileToPerson(zoneFile, publicKeyOrAddress, callback) {
    let zoneFileJson = null;
    try {
        zoneFileJson = zone_file_1.parseZoneFile(zoneFile);
        if (!zoneFileJson.hasOwnProperty('$origin')) {
            zoneFileJson = null;
            throw new Error('zone file is missing an origin');
        }
    }
    catch (e) {
        console.error(e);
    }
    let tokenFileUrl = null;
    if (zoneFileJson && Object.keys(zoneFileJson).length > 0) {
        tokenFileUrl = profileZoneFiles_1.getTokenFileUrl(zoneFileJson);
    }
    else {
        let profile = null;
        try {
            profile = JSON.parse(zoneFile);
            const person = person_1.Person.fromLegacyFormat(profile);
            profile = person.profile();
        }
        catch (error) {
            console.warn(error);
        }
        callback(profile);
        return;
    }
    if (tokenFileUrl) {
        fetch(tokenFileUrl)
            .then(response => response.text())
            .then(responseText => JSON.parse(responseText))
            .then((responseJson) => {
            const tokenRecords = responseJson;
            const token = tokenRecords[0].token;
            const profile = profileTokens_1.extractProfile(token, publicKeyOrAddress);
            callback(profile);
        })
            .catch((error) => {
            console.warn(error);
        });
    }
    else {
        console.warn('Token file url not found');
        callback({});
    }
}
exports.resolveZoneFileToPerson = resolveZoneFileToPerson;
//# sourceMappingURL=personZoneFiles.js.map