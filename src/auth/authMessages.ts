
import 'cross-fetch/polyfill'

// @ts-ignore: Could not find a declaration file for module
import { TokenSigner, SECP256K1Client } from 'jsontokens'
import { makeECPrivateKey, publicKeyToAddress } from '../keys'
import { makeUUID4, nextMonth } from '../utils'
import { makeDIDFromAddress } from '../dids'
import { encryptECIES, decryptECIES } from '../encryption/ec'
import { Logger } from '../logger'
import { DEFAULT_SCOPE } from './authConstants'
import { UserSession } from './userSession'

/** @ignore */
const VERSION = '1.3.1'


/**
 * Generates a ECDSA keypair to
 * use as the ephemeral app transit private key
 * @returns the hex encoded private key
 * @private
 * @ignore
 */
export function generateTransitKey() {
  const transitKey = makeECPrivateKey()
  return transitKey
}


/**
 * Generates an authentication request that can be sent to the Blockstack
 * browser for the user to approve sign in. This authentication request can
 * then be used for sign in by passing it to the [[redirectToSignInWithAuthRequest]]
 * method.
 *
 * *Note*: This method should only be used if you want to use a customized authentication
 * flow. Typically, you'd use [[redirectToSignIn]] which takes care of this
 * under the hood.
 *
 * @param transitPrivateKey - hex-encoded transit key
 * @param redirectURI - location to redirect user to after sign in approval
 * @param manifestURI - location of this app's manifest file
 * @param scopes - the permissions this app is requesting. Defaults to `[store_write]`
 * @param appDomain - the origin of this app
 * @param expiresAt - the time at which this request is no longer valid
 * @param extraParams - Any extra parameters you'd like to pass to the authenticator.
 * Use this to pass options that aren't part of the Blockstack auth spec, but might be supported
 * by special authenticators.
 * @return the authentication request
 */
export function makeAuthRequest(
  transitPrivateKey?: string,
  redirectURI?: string, 
  manifestURI?: string, 
  scopes: string[] = DEFAULT_SCOPE,
  appDomain?: string,
  expiresAt: number = nextMonth().getTime(),
  extraParams: any = {}
): string {
  if (!transitPrivateKey) {
    transitPrivateKey = new UserSession().generateAndStoreTransitKey()
  }

  const getWindowOrigin = (paramName: string) => {
    const origin = typeof window !== 'undefined' && window.location && window.location.origin
    if (!origin) {
      const errMsg = `\`makeAuthRequest\` called without the \`${paramName}\` param specified but`
        + ' the default value uses `window.location.origin` which is not available in this environment'
      Logger.error(errMsg)
      throw new Error(errMsg)
    }
    return origin
  }
  
  if (!redirectURI) {
    redirectURI = `${getWindowOrigin('redirectURI')}/`
  }
  if (!manifestURI) {
    manifestURI = `${getWindowOrigin('manifestURI')}/manifest.json`
  }
  if (!appDomain) {
    appDomain = getWindowOrigin('appDomain')
  }

  /* Create the payload */
  const payload = Object.assign({}, extraParams, {
    jti: makeUUID4(),
    iat: Math.floor(new Date().getTime() / 1000), // JWT times are in seconds
    exp: Math.floor(expiresAt / 1000), // JWT times are in seconds
    iss: null,
    public_keys: [],
    domain_name: appDomain,
    manifest_uri: manifestURI,
    redirect_uri: redirectURI,
    version: VERSION,
    do_not_include_profile: true,
    supports_hub_url: true,
    scopes
  })

  Logger.info(`blockstack.js: generating v${VERSION} auth request`)

  /* Convert the private key to a public key to an issuer */
  const publicKey = SECP256K1Client.derivePublicKey(transitPrivateKey)
  payload.public_keys = [publicKey]
  const address = publicKeyToAddress(publicKey)
  payload.iss = makeDIDFromAddress(address)

  /* Sign and return the token */
  const tokenSigner = new TokenSigner('ES256k', transitPrivateKey)
  const token = tokenSigner.sign(payload)

  return token
}

/**
 * Encrypts the private key for decryption by the given
 * public key.
 * @param publicKey  [description]
 * @param privateKey [description]
 * @returns hex encoded ciphertext
 * @private
 * @ignore
 */
export function encryptPrivateKey(publicKey: string,
                                  privateKey: string): string | null {
  const encryptedObj = encryptECIES(publicKey, privateKey)
  const encryptedJSON = JSON.stringify(encryptedObj)
  return (Buffer.from(encryptedJSON)).toString('hex')
}

/**
 * Decrypts the hex encrypted private key
 * @param privateKey  the private key corresponding to the public
 * key for which the ciphertext was encrypted
 * @param hexedEncrypted the ciphertext
 * @returns  the decrypted private key
 * @throws {Error} if unable to decrypt
 *
 * @private
 * @ignore
 */
export function decryptPrivateKey(privateKey: string,
                                  hexedEncrypted: string): string | null {
  const unhexedString = Buffer.from(hexedEncrypted, 'hex').toString()
  const encryptedObj = JSON.parse(unhexedString)
  const decrypted = decryptECIES(privateKey, encryptedObj)
  if (typeof decrypted !== 'string') {
    throw new Error('Unable to correctly decrypt private key')
  } else {
    return decrypted
  }
}

/**
 * Generates a signed authentication response token for an app. This
 * token is sent back to apps which use contents to access the
 * resources and data requested by the app.
 *
 * @param privateKey the identity key of the Blockstack ID generating
 * the authentication response
 * @param profile the profile object for the Blockstack ID
 * @param username the username of the Blockstack ID if any, otherwise `null`
 * @param metadata an object containing metadata sent as part of the authentication
 * response including `email` if requested and available and a URL to the profile
 * @param coreToken core session token when responding to a legacy auth request
 * or `null` for current direct to gaia authentication requests
 * @param appPrivateKey the application private key. This private key is
 * unique and specific for every Blockstack ID and application combination.
 * @param expiresAt an integer in the same format as
 * `new Date().getTime()`, milliseconds since the Unix epoch
 * @param transitPublicKey the public key provide by the app
 * in its authentication request with which secrets will be encrypted
 * @param hubUrl URL to the write path of the user's Gaia hub
 * @param blockstackAPIUrl URL to the API endpoint to use
 * @param associationToken JWT that binds the app key to the identity key
 * @returns signed and encoded authentication response token
 * @private
 * @ignore
 */
export function makeAuthResponse(privateKey: string,
                                 profile: {} = {},
                                 username: string = null,
                                 metadata: {
                                   email?: string,
                                   profileUrl?: string
                                 },
                                 coreToken: string = null,
                                 appPrivateKey: string = null,
                                 expiresAt: number = nextMonth().getTime(),
                                 transitPublicKey: string = null,
                                 hubUrl: string = null,
                                 blockstackAPIUrl: string = null,
                                 associationToken: string = null): string {
  /* Convert the private key to a public key to an issuer */
  const publicKey = SECP256K1Client.derivePublicKey(privateKey)
  const address = publicKeyToAddress(publicKey)

  /* See if we should encrypt with the transit key */
  let privateKeyPayload = appPrivateKey
  let coreTokenPayload = coreToken
  let additionalProperties = {}
  if (appPrivateKey !== undefined && appPrivateKey !== null) {
    Logger.info(`blockstack.js: generating v${VERSION} auth response`)
    if (transitPublicKey !== undefined && transitPublicKey !== null) {
      privateKeyPayload = encryptPrivateKey(transitPublicKey, appPrivateKey)
      if (coreToken !== undefined && coreToken !== null) {
        coreTokenPayload = encryptPrivateKey(transitPublicKey, coreToken)
      }
    }
    additionalProperties = {
      email: metadata.email ? metadata.email : null,
      profile_url: metadata.profileUrl ? metadata.profileUrl : null,
      hubUrl,
      blockstackAPIUrl,
      associationToken,
      version: VERSION
    }
  } else {
    Logger.info('blockstack.js: generating legacy auth response')
  }

  /* Create the payload */
  const payload = Object.assign({}, {
    jti: makeUUID4(),
    iat: Math.floor(new Date().getTime() / 1000), // JWT times are in seconds
    exp: Math.floor(expiresAt / 1000), // JWT times are in seconds
    iss: makeDIDFromAddress(address),
    private_key: privateKeyPayload,
    public_keys: [publicKey],
    profile,
    username,
    core_token: coreTokenPayload
  }, additionalProperties)

  /* Sign and return the token */
  const tokenSigner = new TokenSigner('ES256k', privateKey)
  return tokenSigner.sign(payload)
}
