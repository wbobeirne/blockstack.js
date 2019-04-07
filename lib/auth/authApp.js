"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const query_string_1 = __importDefault(require("query-string"));
// @ts-ignore: Could not find a declaration file for module
const jsontokens_1 = require("jsontokens");
const index_1 = require("./index");
const utils_1 = require("../utils");
const index_2 = require("../index");
const errors_1 = require("../errors");
const authMessages_1 = require("./authMessages");
const authConstants_1 = require("./authConstants");
const profiles_1 = require("../profiles");
const userSession_1 = require("./userSession");
const config_1 = require("../config");
const logger_1 = require("../logger");
const DEFAULT_PROFILE = {
    '@type': 'Person',
    '@context': 'http://schema.org'
};
/**
 * Check if a user is currently signed in.
 * @method isUserSignedIn
 * @return {Boolean} `true` if the user is signed in, `false` if not.
 */
function isUserSignedIn() {
    console.warn('DEPRECATION WARNING: The static isUserSignedIn() function will be deprecated in '
        + 'the next major release of blockstack.js. Create an instance of UserSession and call the '
        + 'instance method isUserSignedIn().');
    const userSession = new userSession_1.UserSession();
    return userSession.isUserSignedIn();
}
exports.isUserSignedIn = isUserSignedIn;
/**
 * Check if there is a authentication request that hasn't been handled.
 * @return {Boolean} `true` if there is a pending sign in, otherwise `false`
 */
function isSignInPending() {
    console.warn('DEPRECATION WARNING: The static isSignInPending() function will be deprecated in the '
        + 'next major release of blockstack.js. Create an instance of UserSession and call the '
        + 'instance method isSignInPending().');
    const userSession = new userSession_1.UserSession();
    return userSession.isSignInPending();
}
exports.isSignInPending = isSignInPending;
/**
 * Try to process any pending sign in request by returning a `Promise` that resolves
 * to the user data object if the sign in succeeds.
 *
 * @param {String} nameLookupURL - the endpoint against which to verify public
 * keys match claimed username
 * @param {String} authResponseToken - the signed authentication response token
 * @param {String} transitKey - the transit private key that corresponds to the transit public key
 * that was provided in the authentication request
 * @return {Promise} that resolves to the user data object if successful and rejects
 * if handling the sign in request fails or there was no pending sign in request.
 */
/* eslint-disable no-unused-vars, no-use-before-define */
function handlePendingSignIn(nameLookupURL = '', authResponseToken = getAuthResponseToken(), transitKey = '') {
    console.warn('DEPRECATION WARNING: The static handlePendingSignIn() function will be deprecated in the '
        + 'next major release of blockstack.js. Create an instance of UserSession and call the '
        + 'instance method handlePendingSignIn().');
    console.warn('DEPRECATION WARNING: handlePendingSignIn() no long supports setting of nameLookupURL and '
        + 'transitKey. The nameLookupURL and transitKey now defaults to values in the default user session.');
    const userSession = new userSession_1.UserSession();
    return userSession.handlePendingSignIn(authResponseToken);
}
exports.handlePendingSignIn = handlePendingSignIn;
/* eslint-enable no-unused-vars */
/**
 * Retrieve the authentication token from the URL query
 * @return {String} the authentication token if it exists otherwise `null`
 */
function getAuthResponseToken() {
    const queryDict = query_string_1.default.parse(location.search);
    return queryDict.authResponse ? queryDict.authResponse : '';
}
/**
 * Retrieves the user data object. The user's profile is stored in the key `profile`.
 * @return {Object} User data object.
 */
function loadUserData() {
    console.warn('DEPRECATION WARNING: The static loadUserData() function will be deprecated in the '
        + 'next major release of blockstack.js. Create an instance of UserSession and call the '
        + 'instance method loadUserData().');
    const userSession = new userSession_1.UserSession();
    return userSession.loadUserData();
}
exports.loadUserData = loadUserData;
/**
 * Sign the user out and optionally redirect to given location.
 * @param  {String} [redirectURL=null] Location to redirect user to after sign out.
 * @return {void}
 */
function signUserOut(redirectURL = null) {
    console.warn('DEPRECATION WARNING: The static signUserOut() function will be deprecated in the '
        + 'next major release of blockstack.js. Create an instance of UserSession and call the '
        + 'instance method signUserOut().');
    const userSession = new userSession_1.UserSession();
    userSession.signUserOut();
    window.location.href = redirectURL;
}
exports.signUserOut = signUserOut;
/**
 * Generates an authentication request that can be sent to the Blockstack
 * browser for the user to approve sign in. This authentication request can
 * then be used for sign in by passing it to the `redirectToSignInWithAuthRequest`
 * method.
 *
 * *Note: This method should only be used if you want to roll your own authentication
 * flow. Typically you'd use `redirectToSignIn` which takes care of this
 * under the hood.*
 *
 * @param  {String} transitPrivateKey - hex encoded transit private key
 * @param {String} redirectURI - location to redirect user to after sign in approval
 * @param {String} manifestURI - location of this app's manifest file
 * @param {Array<String>} scopes - the permissions this app is requesting
 * @param {String} appDomain - the origin of this app
 * @param {Number} expiresAt - the time at which this request is no longer valid
 * @param {Object} extraParams - Any extra parameters you'd like to pass to the authenticator.
 * Use this to pass options that aren't part of the Blockstack auth spec, but might be supported
 * by special authenticators.
 * @return {String} the authentication request
 */
function makeAuthRequest(transitPrivateKey, redirectURI = `${window.location.origin}/`, manifestURI = `${window.location.origin}/manifest.json`, scopes = authConstants_1.DEFAULT_SCOPE, appDomain = window.location.origin, expiresAt = utils_1.nextMonth().getTime(), extraParams = {}) {
    console.warn('DEPRECATION WARNING: The makeAuthRequest() function will be deprecated in the '
        + 'next major release of blockstack.js. Use UserSession to configure your auth request.');
    const userSession = new userSession_1.UserSession();
    const transitKey = (transitPrivateKey == null)
        ? userSession.generateAndStoreTransitKey() : transitPrivateKey;
    return authMessages_1.makeAuthRequestImpl(transitKey, redirectURI, manifestURI, scopes, appDomain, expiresAt, extraParams);
}
exports.makeAuthRequest = makeAuthRequest;
/**
 * Detects if the native auth-browser is installed and is successfully
 * launched via a custom protocol URI.
 * @param {String} authRequest
 * The encoded authRequest to be used as a query param in the custom URI.
 * @param {String} successCallback
 * The callback that is invoked when the protocol handler was detected.
 * @param {String} failCallback
 * The callback that is invoked when the protocol handler was not detected.
 * @return {void}
 */
function detectProtocolLaunch(authRequest, successCallback, failCallback) {
    // Create a unique ID used for this protocol detection attempt.
    const echoReplyID = Math.random().toString(36).substr(2, 9);
    const echoReplyKeyPrefix = 'echo-reply-';
    const echoReplyKey = `${echoReplyKeyPrefix}${echoReplyID}`;
    // Use localStorage as a reliable cross-window communication method.
    // Create the storage entry to signal a protocol detection attempt for the
    // next browser window to check.
    window.localStorage.setItem(echoReplyKey, Date.now().toString());
    const cleanUpLocalStorage = () => {
        try {
            window.localStorage.removeItem(echoReplyKey);
            // Also clear out any stale echo-reply keys older than 1 hour.
            for (let i = 0; i < window.localStorage.length; i++) {
                const storageKey = window.localStorage.key(i);
                if (storageKey && storageKey.startsWith(echoReplyKeyPrefix)) {
                    const storageValue = window.localStorage.getItem(storageKey);
                    if (storageValue === 'success' || (Date.now() - parseInt(storageValue, 10)) > 3600000) {
                        window.localStorage.removeItem(storageKey);
                    }
                }
            }
        }
        catch (err) {
            logger_1.Logger.error('Exception cleaning up echo-reply entries in localStorage');
            logger_1.Logger.error(err);
        }
    };
    const detectionTimeout = 1000;
    let redirectToWebAuthTimer = 0;
    const cancelWebAuthRedirectTimer = () => {
        if (redirectToWebAuthTimer) {
            window.clearTimeout(redirectToWebAuthTimer);
            redirectToWebAuthTimer = 0;
        }
    };
    const startWebAuthRedirectTimer = (timeout = detectionTimeout) => {
        cancelWebAuthRedirectTimer();
        redirectToWebAuthTimer = window.setTimeout(() => {
            if (redirectToWebAuthTimer) {
                cancelWebAuthRedirectTimer();
                let nextFunc;
                if (window.localStorage.getItem(echoReplyKey) === 'success') {
                    logger_1.Logger.info('Protocol echo reply detected.');
                    nextFunc = successCallback;
                }
                else {
                    logger_1.Logger.info('Protocol handler not detected.');
                    nextFunc = failCallback;
                }
                failCallback = () => { };
                successCallback = () => { };
                cleanUpLocalStorage();
                // Briefly wait since localStorage changes can 
                // sometimes be ignored when immediately redirected.
                setTimeout(() => nextFunc(), 100);
            }
        }, timeout);
    };
    startWebAuthRedirectTimer();
    const inputPromptTracker = document.createElement('input');
    inputPromptTracker.type = 'text';
    const elStyle = inputPromptTracker.style;
    // Prevent this element from inherited any css.
    elStyle.all = 'initial';
    // Setting display=none on an element prevents them from being focused/blurred.
    // So hide the element using other properties..
    inputPromptTracker.style.opacity = '0';
    inputPromptTracker.style.filter = 'alpha(opacity=0)';
    inputPromptTracker.style.height = '0';
    inputPromptTracker.style.width = '0';
    // If the the focus of a page element is immediately changed then this likely indicates 
    // the protocol handler is installed, and the browser is prompting the user if they want 
    // to open the application. 
    const inputBlurredFunc = () => {
        // Use a timeout of 100ms to ignore instant toggles between blur and focus.
        // Browsers often perform an instant blur & focus when the protocol handler is working
        // but not showing any browser prompts, so we want to ignore those instances.
        let isRefocused = false;
        inputPromptTracker.addEventListener('focus', () => { isRefocused = true; }, { once: true, capture: true });
        setTimeout(() => {
            if (redirectToWebAuthTimer && !isRefocused) {
                logger_1.Logger.info('Detected possible browser prompt for opening the protocol handler app.');
                window.clearTimeout(redirectToWebAuthTimer);
                inputPromptTracker.addEventListener('focus', () => {
                    if (redirectToWebAuthTimer) {
                        logger_1.Logger.info('Possible browser prompt closed, restarting auth redirect timeout.');
                        startWebAuthRedirectTimer();
                    }
                }, { once: true, capture: true });
            }
        }, 100);
    };
    inputPromptTracker.addEventListener('blur', inputBlurredFunc, { once: true, capture: true });
    setTimeout(() => inputPromptTracker.removeEventListener('blur', inputBlurredFunc), 200);
    // Flow complains without this check.
    if (document.body)
        document.body.appendChild(inputPromptTracker);
    inputPromptTracker.focus();
    // Detect if document.visibility is immediately changed which is a strong 
    // indication that the protocol handler is working. We don't know for sure and 
    // can't predict future browser changes, so only increase the redirect timeout.
    // This reduces the probability of a false-negative (where local auth works, but 
    // the original page was redirect to web auth because something took too long),
    const pageVisibilityChanged = () => {
        if (document.hidden && redirectToWebAuthTimer) {
            logger_1.Logger.info('Detected immediate page visibility change (protocol handler probably working).');
            startWebAuthRedirectTimer(3000);
        }
    };
    document.addEventListener('visibilitychange', pageVisibilityChanged, { once: true, capture: true });
    setTimeout(() => document.removeEventListener('visibilitychange', pageVisibilityChanged), 500);
    // Listen for the custom protocol echo reply via localStorage update event.
    window.addEventListener('storage', function replyEventListener(event) {
        if (event.key === echoReplyKey && window.localStorage.getItem(echoReplyKey) === 'success') {
            // Custom protocol worked, cancel the web auth redirect timer.
            cancelWebAuthRedirectTimer();
            inputPromptTracker.removeEventListener('blur', inputBlurredFunc);
            logger_1.Logger.info('Protocol echo reply detected from localStorage event.');
            // Clean up event listener and localStorage.
            window.removeEventListener('storage', replyEventListener);
            const nextFunc = successCallback;
            successCallback = () => { };
            failCallback = () => { };
            cleanUpLocalStorage();
            // Briefly wait since localStorage changes can sometimes 
            // be ignored when immediately redirected.
            setTimeout(() => nextFunc(), 100);
        }
    }, false);
    // Use iframe technique for launching the protocol URI rather than setting `window.location`.
    // This method prevents browsers like Safari, Opera, Firefox from showing error prompts
    // about unknown protocol handler when app is not installed, and avoids an empty
    // browser tab when the app is installed. 
    logger_1.Logger.info('Attempting protocol launch via iframe injection.');
    const locationSrc = `${utils_1.BLOCKSTACK_HANDLER}:${authRequest}&echo=${echoReplyID}`;
    const iframe = document.createElement('iframe');
    const iframeStyle = iframe.style;
    iframeStyle.all = 'initial';
    iframe.style.display = 'none';
    iframe.src = locationSrc;
    // Flow complains without this check.
    if (document.body) {
        document.body.appendChild(iframe);
    }
    else {
        logger_1.Logger.error('document.body is null when attempting iframe injection for protoocol URI launch');
    }
}
/**
 * Redirects the user to the Blockstack browser to approve the sign in request
 * given.
 *
 * The user is redirected to the `blockstackIDHost` if the `blockstack:`
 * protocol handler is not detected. Please note that the protocol handler detection
 * does not work on all browsers.
 * @param  {UserSession} caller - the instance calling this method
 * @param  {String} authRequest - the authentication request generated by `makeAuthRequest`
 * @param  {String} blockstackIDHost - the URL to redirect the user to if the blockstack
 *                                     protocol handler is not detected
 * @return {void}
 * @private
 */
function redirectToSignInWithAuthRequestImpl(caller, authRequest) {
    let httpsURI = `${authConstants_1.DEFAULT_BLOCKSTACK_HOST}?authRequest=${authRequest}`;
    if (caller.appConfig
        && caller.appConfig.authenticatorURL) {
        httpsURI = `${caller.appConfig.authenticatorURL}?authRequest=${authRequest}`;
    }
    // If they're on a mobile OS, always redirect them to HTTPS site
    if (/Android|webOS|iPhone|iPad|iPod|Opera Mini/i.test(navigator.userAgent)) {
        logger_1.Logger.info('detected mobile OS, sending to https');
        window.location.href = httpsURI;
        return;
    }
    function successCallback() {
        logger_1.Logger.info('protocol handler detected');
        // The detection function should open the link for us
    }
    function failCallback() {
        logger_1.Logger.warn('protocol handler not detected');
        window.location.href = httpsURI;
    }
    detectProtocolLaunch(authRequest, successCallback, failCallback);
}
exports.redirectToSignInWithAuthRequestImpl = redirectToSignInWithAuthRequestImpl;
/**
 * Generates an authentication request and redirects the user to the Blockstack
 * browser to approve the sign in request.
 *
 * Please note that this requires that the web browser properly handles the
 * `blockstack:` URL protocol handler.
 *
 * Most applications should use this
 * method for sign in unless they require more fine grained control over how the
 * authentication request is generated. If your app falls into this category,
 * use `makeAuthRequest` and `redirectToSignInWithAuthRequest` to build your own sign in process.
 *
 * @param {String} [redirectURI=`${window.location.origin}/`]
 * The location to which the identity provider will redirect the user after
 * the user approves sign in.
 * @param  {String} [manifestURI=`${window.location.origin}/manifest.json`]
 * Location of the manifest file.
 * @param  {Array} [scopes=DEFAULT_SCOPE] Defaults to requesting write access to
 * this app's data store.
 * An array of strings indicating which permissions this app is requesting.
 * @return {void}
 */
function redirectToSignIn(redirectURI = `${window.location.origin}/`, manifestURI = `${window.location.origin}/manifest.json`, scopes = authConstants_1.DEFAULT_SCOPE) {
    console.warn('DEPRECATION WARNING: The static redirectToSignIn() function will be deprecated in the '
        + 'next major release of blockstack.js. Create an instance of UserSession and call the '
        + 'instance method redirectToSignIn().');
    const authRequest = makeAuthRequest(null, redirectURI, manifestURI, scopes);
    redirectToSignInWithAuthRequest(authRequest);
}
exports.redirectToSignIn = redirectToSignIn;
/**
 * Generates an authentication request and redirects the user to the Blockstack
 * browser to approve the sign in request.
 *
 * Please note that this requires that the web browser properly handles the
 * `blockstack:` URL protocol handler.
 *
 * Most web applications should use this
 * method for sign in unless they require more fine grained control over how the
 * authentication request is generated. If your app falls into this category,
 * use `makeAuthRequest`,
 * and `redirectToSignInWithAuthRequest` to build your own sign in process.
 * @param {UserSession} caller - the instance calling this function
 * @return {void}
 * @private
 */
function redirectToSignInImpl(caller) {
    const transitKey = caller.generateAndStoreTransitKey();
    const authRequest = caller.makeAuthRequest(transitKey);
    redirectToSignInWithAuthRequestImpl(caller, authRequest);
}
exports.redirectToSignInImpl = redirectToSignInImpl;
/**
 * Try to process any pending sign in request by returning a `Promise` that resolves
 * to the user data object if the sign in succeeds.
 *
 * @param {UserSession} caller - the instance calling this function
 * @param {String} authResponseToken - the signed authentication response token
 * @return {Promise} that resolves to the user data object if successful and rejects
 * if handling the sign in request fails or there was no pending sign in request.
 * @private
 */
function handlePendingSignInImpl(caller, authResponseToken) {
    const transitKey = caller.store.getSessionData().transitKey;
    const coreNodeSessionValue = caller.store.getSessionData().coreNode;
    let nameLookupURL = null;
    if (!coreNodeSessionValue) {
        const tokenPayload = jsontokens_1.decodeToken(authResponseToken).payload;
        if (utils_1.isLaterVersion(tokenPayload.version, '1.3.0')
            && tokenPayload.blockstackAPIUrl !== null && tokenPayload.blockstackAPIUrl !== undefined) {
            // override globally
            logger_1.Logger.info(`Overriding ${config_1.config.network.blockstackAPIUrl} `
                + `with ${tokenPayload.blockstackAPIUrl}`);
            config_1.config.network.blockstackAPIUrl = tokenPayload.blockstackAPIUrl;
        }
        nameLookupURL = `${config_1.config.network.blockstackAPIUrl}${authConstants_1.NAME_LOOKUP_PATH}`;
    }
    else {
        nameLookupURL = `${coreNodeSessionValue}${authConstants_1.NAME_LOOKUP_PATH}`;
    }
    return index_1.verifyAuthResponse(authResponseToken, nameLookupURL)
        .then((isValid) => {
        if (!isValid) {
            throw new errors_1.LoginFailedError('Invalid authentication response.');
        }
        const tokenPayload = jsontokens_1.decodeToken(authResponseToken).payload;
        // TODO: real version handling
        let appPrivateKey = tokenPayload.private_key;
        let coreSessionToken = tokenPayload.core_token;
        if (utils_1.isLaterVersion(tokenPayload.version, '1.1.0')) {
            if (transitKey !== undefined && transitKey != null) {
                if (tokenPayload.private_key !== undefined && tokenPayload.private_key !== null) {
                    try {
                        appPrivateKey = authMessages_1.decryptPrivateKey(transitKey, tokenPayload.private_key);
                    }
                    catch (e) {
                        logger_1.Logger.warn('Failed decryption of appPrivateKey, will try to use as given');
                        try {
                            utils_1.hexStringToECPair(tokenPayload.private_key);
                        }
                        catch (ecPairError) {
                            throw new errors_1.LoginFailedError('Failed decrypting appPrivateKey. Usually means'
                                + ' that the transit key has changed during login.');
                        }
                    }
                }
                if (coreSessionToken !== undefined && coreSessionToken !== null) {
                    try {
                        coreSessionToken = authMessages_1.decryptPrivateKey(transitKey, coreSessionToken);
                    }
                    catch (e) {
                        logger_1.Logger.info('Failed decryption of coreSessionToken, will try to use as given');
                    }
                }
            }
            else {
                throw new errors_1.LoginFailedError('Authenticating with protocol > 1.1.0 requires transit'
                    + ' key, and none found.');
            }
        }
        let hubUrl = authConstants_1.BLOCKSTACK_DEFAULT_GAIA_HUB_URL;
        let gaiaAssociationToken;
        if (utils_1.isLaterVersion(tokenPayload.version, '1.2.0')
            && tokenPayload.hubUrl !== null && tokenPayload.hubUrl !== undefined) {
            hubUrl = tokenPayload.hubUrl;
        }
        if (utils_1.isLaterVersion(tokenPayload.version, '1.3.0')
            && tokenPayload.associationToken !== null && tokenPayload.associationToken !== undefined) {
            gaiaAssociationToken = tokenPayload.associationToken;
        }
        const userData = {
            username: tokenPayload.username,
            profile: tokenPayload.profile,
            email: tokenPayload.email,
            decentralizedID: tokenPayload.iss,
            identityAddress: index_2.getAddressFromDID(tokenPayload.iss),
            appPrivateKey,
            coreSessionToken,
            authResponseToken,
            hubUrl,
            gaiaAssociationToken
        };
        const profileURL = tokenPayload.profile_url;
        if ((userData.profile === null
            || userData.profile === undefined)
            && profileURL !== undefined && profileURL !== null) {
            return fetch(profileURL)
                .then((response) => {
                if (!response.ok) { // return blank profile if we fail to fetch
                    userData.profile = Object.assign({}, DEFAULT_PROFILE);
                    const sessionData = caller.store.getSessionData();
                    sessionData.userData = userData;
                    caller.store.setSessionData(sessionData);
                    return userData;
                }
                else {
                    return response.text()
                        .then(responseText => JSON.parse(responseText))
                        .then(wrappedProfile => profiles_1.extractProfile(wrappedProfile[0].token))
                        .then((profile) => {
                        const sessionData = caller.store.getSessionData();
                        userData.profile = profile;
                        sessionData.userData = userData;
                        caller.store.setSessionData(sessionData);
                        return userData;
                    });
                }
            });
        }
        else {
            const sessionData = caller.store.getSessionData();
            userData.profile = tokenPayload.profile;
            sessionData.userData = userData;
            caller.store.setSessionData(sessionData);
            return userData;
        }
    });
}
exports.handlePendingSignInImpl = handlePendingSignInImpl;
/**
 * Retrieves the user data object. The user's profile is stored in the key `profile`.
 *
 * @param {UserSession} caller - the instance calling this function
 * @return {Object} User data object.
 * @ignore
 */
function loadUserDataImpl(caller) {
    const userData = caller.store.getSessionData().userData;
    if (!userData) {
        throw new errors_1.InvalidStateError('No user data found. Did the user sign in?');
    }
    return userData;
}
exports.loadUserDataImpl = loadUserDataImpl;
/**
 * Redirects the user to the Blockstack browser to approve the sign in request
 * given.
 *
 * The user is redirected to the `blockstackIDHost` if the `blockstack:`
 * protocol handler is not detected. Please note that the protocol handler detection
 * does not work on all browsers.
 * @param  {String} authRequest - the authentication request generated by `makeAuthRequest`
 * @param  {String} blockstackIDHost - the URL to redirect the user to if the blockstack
 *                                     protocol handler is not detected
 * @return {void}
 */
function redirectToSignInWithAuthRequest(authRequest, blockstackIDHost = authConstants_1.DEFAULT_BLOCKSTACK_HOST) {
    console.warn('DEPRECATION WARNING: The static redirectToSignInWithAuthRequest() function will '
        + 'be deprecated in the next major release of blockstack.js. Create an instance of UserSession '
        + 'and call the instance method redirectToSignInWithAuthRequest().');
    const userSession = new userSession_1.UserSession();
    const sessionAuthRequest = (authRequest == null)
        ? userSession.makeAuthRequest(userSession.generateAndStoreTransitKey()) : authRequest;
    userSession.appConfig.authenticatorURL = blockstackIDHost;
    redirectToSignInWithAuthRequestImpl(userSession, sessionAuthRequest);
}
exports.redirectToSignInWithAuthRequest = redirectToSignInWithAuthRequest;
//# sourceMappingURL=authApp.js.map