// Copyright (c) 2023 Apple Inc. Licensed under MIT License.

import * as jose from 'jose'

import { X509Certificate } from '@peculiar/x509';
import { Environment } from './models/Environment';
import { JWSTransactionDecodedPayload, JWSTransactionDecodedPayloadValidator } from './models/JWSTransactionDecodedPayload';
import { ResponseBodyV2DecodedPayload, ResponseBodyV2DecodedPayloadValidator } from './models/ResponseBodyV2DecodedPayload';
import { JWSRenewalInfoDecodedPayload, JWSRenewalInfoDecodedPayloadValidator } from './models/JWSRenewalInfoDecodedPayload';
import { DecodedRealtimeRequestBody, DecodedRealtimeRequestBodyValidator } from './models/DecodedRealtimeRequestBody';
import { Validator } from './models/Validator';
import { DecodedSignedData } from './models/DecodedSignedData';
import { AppTransaction, AppTransactionValidator } from './models/AppTransaction';

const MAX_SKEW = 60000

const MAXIMUM_CACHE_SIZE = 32 // There are unlikely to be more than a couple keys at once
const CACHE_TIME_LIMIT = 15 * 60 * 1_000 // 15 minutes

// ===== Conversion utilities =====

function base64ToUint8Array(b64: string): Uint8Array {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

function uint8ArrayToBase64(arr: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < arr.length; i++) binary += String.fromCharCode(arr[i])
  return btoa(binary)
}

function uint8ArrayToHex(arr: Uint8Array): string {
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('')
}

function hexToUint8Array(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2)
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16)
  return bytes
}

// ===== DER encoding =====

function derEncodeLength(length: number): Uint8Array {
  if (length < 0x80) return new Uint8Array([length])
  const bytes: number[] = []
  let temp = length
  while (temp > 0) { bytes.unshift(temp & 0xFF); temp >>= 8 }
  return new Uint8Array([0x80 | bytes.length, ...bytes])
}

function derTag(tag: number, content: Uint8Array): Uint8Array {
  const len = derEncodeLength(content.length)
  const result = new Uint8Array(1 + len.length + content.length)
  result[0] = tag
  result.set(len, 1)
  result.set(content, 1 + len.length)
  return result
}

function derSequence(items: Uint8Array[]): Uint8Array {
  let totalLen = 0
  for (const item of items) totalLen += item.length
  const content = new Uint8Array(totalLen)
  let offset = 0
  for (const item of items) { content.set(item, offset); offset += item.length }
  return derTag(0x30, content)
}

function derOctetString(data: Uint8Array): Uint8Array { return derTag(0x04, data) }

function derInteger(data: Uint8Array): Uint8Array {
  if (data.length > 0 && (data[0] & 0x80) !== 0) {
    const padded = new Uint8Array(data.length + 1)
    padded.set(data, 1)
    return derTag(0x02, padded)
  }
  return derTag(0x02, data)
}

function derEncodeOID(oid: string): Uint8Array {
  const parts = oid.split('.').map(Number)
  const bytes: number[] = [parts[0] * 40 + parts[1]]
  for (let i = 2; i < parts.length; i++) {
    let val = parts[i]
    if (val < 128) { bytes.push(val) }
    else {
      const enc: number[] = [val & 0x7F]
      val >>= 7
      while (val > 0) { enc.push(0x80 | (val & 0x7F)); val >>= 7 }
      enc.reverse()
      bytes.push(...enc)
    }
  }
  return derTag(0x06, new Uint8Array(bytes))
}

// ===== DER parsing =====

interface DERElement {
  tag: number; offset: number; headerLen: number; length: number
}

function derParse(data: Uint8Array, offset: number): DERElement {
  const tag = data[offset]
  const firstLen = data[offset + 1]
  let headerLen: number, length: number
  if (firstLen < 0x80) { headerLen = 2; length = firstLen }
  else if (firstLen === 0x80) { headerLen = 2; length = data.length - offset - 2 }
  else {
    const n = firstLen & 0x7F; length = 0
    for (let i = 0; i < n; i++) length = (length << 8) | data[offset + 2 + i]
    headerLen = 2 + n
  }
  return { tag, offset, headerLen, length }
}

function derContent(data: Uint8Array, e: DERElement): Uint8Array {
  return data.slice(e.offset + e.headerLen, e.offset + e.headerLen + e.length)
}

function derTLV(data: Uint8Array, e: DERElement): Uint8Array {
  return data.slice(e.offset, e.offset + e.headerLen + e.length)
}

function derChildren(data: Uint8Array, parent: DERElement): DERElement[] {
  const out: DERElement[] = []
  const end = parent.offset + parent.headerLen + parent.length
  let pos = parent.offset + parent.headerLen
  while (pos < end) { const c = derParse(data, pos); out.push(c); pos = c.offset + c.headerLen + c.length }
  return out
}

function derDecodeOID(data: Uint8Array, e: DERElement): string {
  const c = derContent(data, e)
  const parts: number[] = [Math.floor(c[0] / 40), c[0] % 40]
  let val = 0
  for (let i = 1; i < c.length; i++) {
    val = (val << 7) | (c[i] & 0x7F)
    if ((c[i] & 0x80) === 0) { parts.push(val); val = 0 }
  }
  return parts.join('.')
}

// ===== X.509 helpers =====

function hasExtension(cert: X509Certificate, oid: string): boolean {
  return cert.extensions.some(ext => ext.type === oid)
}

function isCA(cert: X509Certificate): boolean {
  const bcExt = cert.extensions.find(ext => ext.type === '2.5.29.19')
  if (!bcExt) return false
  const v = new Uint8Array(bcExt.value)
  if (v.length < 5 || v[0] !== 0x30) return false
  return v[2] === 0x01 && v[3] === 0x01 && v[4] === 0xFF
}

function hasExtKeyUsage(cert: X509Certificate, oid: string): boolean {
  const ekuExt = cert.extensions.find(ext => ext.type === '2.5.29.37')
  if (!ekuExt) return false
  const d = new Uint8Array(ekuExt.value)
  const root = derParse(d, 0)
  for (const c of derChildren(d, root)) {
    if (derDecodeOID(d, c) === oid) return true
  }
  return false
}

function getTBSChildren(cert: X509Certificate): { data: Uint8Array; children: DERElement[] } {
  const data = new Uint8Array(cert.rawData)
  const certSeq = derParse(data, 0)
  const tbs = derChildren(data, certSeq)[0]
  return { data, children: derChildren(data, tbs) }
}

function getSubjectNameDER(cert: X509Certificate): Uint8Array {
  const { data, children } = getTBSChildren(cert)
  const idx = children[0].tag === 0xA0 ? 5 : 4
  return derTLV(data, children[idx])
}

function getSPKIKeyBytes(cert: X509Certificate): Uint8Array {
  // Returns key_bytes only (no unused_bits_byte) — used for both CertID hashing and responder ID KeyHash
  const { data, children } = getTBSChildren(cert)
  const spkiIdx = children[0].tag === 0xA0 ? 6 : 5
  const spkiChildren = derChildren(data, children[spkiIdx])
  return derContent(data, spkiChildren[1]).slice(1) // skip unused bits byte
}

// ===== OCSP =====

const SHA256_OID = '2.16.840.1.101.3.4.2.1'

const SIG_ALG_MAP: { [oid: string]: { name: string; hash: string; namedCurve?: string; componentSize?: number } } = {
  '1.2.840.10045.4.3.2': { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256', componentSize: 32 },
  '1.2.840.10045.4.3.3': { name: 'ECDSA', hash: 'SHA-384', namedCurve: 'P-384', componentSize: 48 },
  '1.2.840.10045.4.3.4': { name: 'ECDSA', hash: 'SHA-512', namedCurve: 'P-521', componentSize: 66 },
  '1.2.840.113549.1.1.11': { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
  '1.2.840.113549.1.1.12': { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' },
  '1.2.840.113549.1.1.13': { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' },
}

function getOCSPUrl(cert: X509Certificate): string | null {
  const aiaExt = cert.extensions.find(ext => ext.type === '1.3.6.1.5.5.7.1.1')
  if (!aiaExt) return null
  const d = new Uint8Array(aiaExt.value)
  for (const desc of derChildren(d, derParse(d, 0))) {
    const ch = derChildren(d, desc)
    if (ch.length >= 2 && derDecodeOID(d, ch[0]) === '1.3.6.1.5.5.7.48.1' && (ch[1].tag & 0x1F) === 6) {
      return new TextDecoder().decode(derContent(d, ch[1]))
    }
  }
  return null
}

async function buildOCSPRequest(cert: X509Certificate, issuer: X509Certificate): Promise<Uint8Array> {
  const nameHash = new Uint8Array(await crypto.subtle.digest('SHA-256', getSubjectNameDER(issuer)))
  const keyHash = new Uint8Array(await crypto.subtle.digest('SHA-256', getSPKIKeyBytes(issuer)))
  const serial = hexToUint8Array(cert.serialNumber)

  const certId = derSequence([
    derSequence([derEncodeOID(SHA256_OID), new Uint8Array([0x05, 0x00])]),
    derOctetString(nameHash),
    derOctetString(keyHash),
    derInteger(serial)
  ])
  return derSequence([derSequence([derSequence([derSequence([certId])])])])
}

interface OCSPCertID { alg: string; nameHash: string; keyHash: string; serial: string }
interface OCSPSingleResponse { certId: OCSPCertID; status: string; thisUpdate: string; nextUpdate: string }
interface OCSPParsed {
  sigAlgOid: string; signature: Uint8Array; tbsResponseDataTLV: Uint8Array
  respIdType: 'key' | 'name'; respIdValue: Uint8Array
  responses: OCSPSingleResponse[]; certs: Uint8Array[]
}

function parseOCSPResponse(data: Uint8Array): OCSPParsed {
  const root = derParse(data, 0)
  const rootCh = derChildren(data, root)
  if (derContent(data, rootCh[0])[0] !== 0) throw new Error('OCSP response not successful')

  // responseBytes [0] EXPLICIT → ResponseBytes SEQUENCE → OCTET STRING → BasicOCSPResponse
  const rbSeqCh = derChildren(data, derChildren(data, rootCh[1])[0])
  const basicData = derContent(data, rbSeqCh[1])
  const basicCh = derChildren(basicData, derParse(basicData, 0))

  // ResponseData, signatureAlgorithm, signature, [0] certs
  const tbsResponseDataTLV = derTLV(basicData, basicCh[0])
  const sigAlgOid = derDecodeOID(basicData, derChildren(basicData, basicCh[1])[0])
  const sigContent = derContent(basicData, basicCh[2])
  const signature = sigContent.slice(1) // skip unused bits byte

  // Parse ResponseData
  const rdCh = derChildren(basicData, basicCh[0])
  let i = 0
  if (rdCh[i].tag === 0xA0) i++ // skip version

  // ResponderID [1]=byName [2]=byKey
  const rid = rdCh[i]; i++
  const ridTag = rid.tag & 0x1F
  let respIdType: 'key' | 'name'
  let respIdValue: Uint8Array
  if (ridTag === 1) {
    respIdType = 'name'
    respIdValue = derContent(basicData, rid) // Name TLV
  } else {
    respIdType = 'key'
    const inner = derChildren(basicData, rid)[0]
    respIdValue = derContent(basicData, inner) // key hash bytes
  }

  i++ // skip producedAt

  // responses SEQUENCE OF SingleResponse
  const responses: OCSPSingleResponse[] = []
  for (const sr of derChildren(basicData, rdCh[i])) {
    const srCh = derChildren(basicData, sr)
    const cidCh = derChildren(basicData, srCh[0])
    const cidAlg = derDecodeOID(basicData, derChildren(basicData, cidCh[0])[0])
    const certId: OCSPCertID = {
      alg: cidAlg,
      nameHash: uint8ArrayToHex(derContent(basicData, cidCh[1])),
      keyHash: uint8ArrayToHex(derContent(basicData, cidCh[2])),
      serial: uint8ArrayToHex(derContent(basicData, cidCh[3]))
    }
    const status = (srCh[1].tag & 0x1F) === 0 ? 'good' : (srCh[1].tag & 0x1F) === 1 ? 'revoked' : 'unknown'
    const thisUpdate = new TextDecoder().decode(derContent(basicData, srCh[2]))
    let nextUpdate = ''
    if (srCh.length > 3 && (srCh[3].tag & 0xC0) === 0x80) {
      const inner = derChildren(basicData, srCh[3])[0]
      nextUpdate = new TextDecoder().decode(derContent(basicData, inner))
    }
    responses.push({ certId, status, thisUpdate, nextUpdate })
  }

  // Optional certs [0] EXPLICIT SEQUENCE OF Certificate
  const certs: Uint8Array[] = []
  if (basicCh.length > 3 && (basicCh[3].tag & 0xC0) === 0x80) {
    const certsCh = derChildren(basicData, derChildren(basicData, basicCh[3])[0])
    for (const c of certsCh) certs.push(derTLV(basicData, c))
  }

  return { sigAlgOid, signature, tbsResponseDataTLV, respIdType, respIdValue, responses, certs }
}

function ecdsaDerToRaw(derSig: Uint8Array, componentSize: number): Uint8Array {
  const seqCh = derChildren(derSig, derParse(derSig, 0))
  const r = derContent(derSig, seqCh[0])
  const s = derContent(derSig, seqCh[1])
  const raw = new Uint8Array(componentSize * 2)
  const rStart = r[0] === 0 ? 1 : 0; const rLen = r.length - rStart
  raw.set(r.slice(rStart), componentSize - rLen)
  const sStart = s[0] === 0 ? 1 : 0; const sLen = s.length - sStart
  raw.set(s.slice(sStart), componentSize * 2 - sLen)
  return raw
}

// ===== End utilities =====

class CacheValue {
  public publicKey: CryptoKey
  public cacheExpiry: number

  constructor(publicKey: CryptoKey, cacheExpiry: number) {
    this.publicKey = publicKey
    this.cacheExpiry = cacheExpiry
  }
}

/**
 * A class providing utility methods for verifying and decoding App Store signed data.
 *
 * Example Usage:
 * ```ts
 * const verifier = new SignedDataVerifier([appleRoot, appleRoot2], true, Environment.SANDBOX, "com.example")
 *
 * try {
 *     const decodedNotification = verifier.verifyAndDecodeNotification("ey...")
 *     console.log(decodedNotification)
 * } catch (e) {
 *     console.error(e)
 * }
 * ```
 */
export class SignedDataVerifier {
    private JWSRenewalInfoDecodedPayloadValidator = new JWSRenewalInfoDecodedPayloadValidator()
    private JWSTransactionDecodedPayloadValidator = new JWSTransactionDecodedPayloadValidator()
    private responseBodyV2DecodedPayloadValidator = new ResponseBodyV2DecodedPayloadValidator()
    private appTransactionValidator = new AppTransactionValidator()
    private decodedRealtimeRequestBodyValidator = new DecodedRealtimeRequestBodyValidator()

    protected rootCertificates: X509Certificate[]
    protected enableOnlineChecks: boolean
    protected bundleId: string
    protected appAppleId?: number
    protected environment: Environment
    protected verifiedPublicKeyCache: { [index: string]: CacheValue }

    /**
     *
     * @param appleRootCertificates A list of DER-encoded root certificates
     * @param enableOnlineChecks Whether to enable revocation checking and check expiration using the current date
     * @param environment The App Store environment to target for checks
     * @param bundleId The app's bundle identifier
     * @param appAppleId The app's identifier, omitted in the sandbox environment
     */
    constructor(appleRootCertificates: Uint8Array[], enableOnlineChecks: boolean, environment: Environment, bundleId: string, appAppleId?: number) {
      this.rootCertificates = appleRootCertificates.map(cert => new X509Certificate(cert))
      this.enableOnlineChecks = enableOnlineChecks
      this.bundleId = bundleId;
      this.environment = environment
      this.appAppleId = appAppleId
      this.verifiedPublicKeyCache = {}
      if (environment === Environment.PRODUCTION && appAppleId === undefined) {
        throw new Error("appAppleId is required when the environment is Production")
      }
    }

    /**
     * Verifies and decodes a signedTransaction obtained from the App Store Server API, an App Store Server Notification, or from a device
     * See {@link https://developer.apple.com/documentation/appstoreserverapi/jwstransaction JWSTransaction}
     *
     * @param signedTransaction The signedTransaction field
     * @return The decoded transaction info after verification
     * @throws VerificationException Thrown if the data could not be verified
     */
    async verifyAndDecodeTransaction(signedTransactionInfo: string): Promise<JWSTransactionDecodedPayload> {
      const decodedJWT: JWSTransactionDecodedPayload = await this.verifyJWT(signedTransactionInfo, this.JWSTransactionDecodedPayloadValidator, this.extractSignedDate);
      if (decodedJWT.bundleId !== this.bundleId) {
        throw new VerificationException(VerificationStatus.INVALID_APP_IDENTIFIER)
      }
      if (decodedJWT.environment !== this.environment) {
        throw new VerificationException(VerificationStatus.INVALID_ENVIRONMENT)
      }
      return decodedJWT;
    }

    /**
     * Verifies and decodes a signedRenewalInfo obtained from the App Store Server API, an App Store Server Notification, or from a device
     * See {@link https://developer.apple.com/documentation/appstoreserverapi/jwsrenewalinfo JWSRenewalInfo}
     *
     * @param signedRenewalInfo The signedRenewalInfo field
     * @return The decoded renewal info after verification
     * @throws VerificationException Thrown if the data could not be verified
     */
    async verifyAndDecodeRenewalInfo(signedRenewalInfo: string): Promise<JWSRenewalInfoDecodedPayload> {
      const decodedRenewalInfo: JWSRenewalInfoDecodedPayload = await this.verifyJWT(signedRenewalInfo, this.JWSRenewalInfoDecodedPayloadValidator, this.extractSignedDate);
      const environment = decodedRenewalInfo.environment
      if (this.environment !== environment) {
        throw new VerificationException(VerificationStatus.INVALID_ENVIRONMENT)
      }
      return decodedRenewalInfo
    }

    /**
     * Verifies and decodes an App Store Server Notification signedPayload
     * See {@link https://developer.apple.com/documentation/appstoreservernotifications/signedpayload signedPayload}
     *
     * @param signedPayload The payload received by your server
     * @return The decoded payload after verification
     * @throws VerificationException Thrown if the data could not be verified
     */
    async verifyAndDecodeNotification(signedPayload: string): Promise<ResponseBodyV2DecodedPayload> {
      const decodedJWT: ResponseBodyV2DecodedPayload = await this.verifyJWT(signedPayload, this.responseBodyV2DecodedPayloadValidator, this.extractSignedDate);
      let appAppleId: number | undefined
      let bundleId: string | undefined
      let environment: string | undefined
      if (decodedJWT.data) {
        appAppleId = decodedJWT.data.appAppleId
        bundleId = decodedJWT.data.bundleId
        environment = decodedJWT.data.environment
      } else if (decodedJWT.summary) {
        appAppleId = decodedJWT.summary.appAppleId
        bundleId = decodedJWT.summary.bundleId
        environment = decodedJWT.summary.environment
      } else if (decodedJWT.externalPurchaseToken) {
        appAppleId = decodedJWT.externalPurchaseToken.appAppleId
        bundleId = decodedJWT.externalPurchaseToken.bundleId
        if (decodedJWT.externalPurchaseToken.externalPurchaseId && decodedJWT.externalPurchaseToken.externalPurchaseId.startsWith("SANDBOX")) {
          environment = Environment.SANDBOX
        } else {
          environment = Environment.PRODUCTION
        }
      } else if (decodedJWT.appData) {
        appAppleId = decodedJWT.appData.appAppleId
        bundleId = decodedJWT.appData.bundleId
        environment = decodedJWT.appData.environment
      }
      this.verifyNotification(bundleId, appAppleId, environment)
      return decodedJWT
    }

    protected verifyNotification(bundleId?: string, appAppleId?: number, environment?: string) {
      if (this.bundleId !== bundleId || (this.environment === Environment.PRODUCTION && this.appAppleId !== appAppleId)) {
        throw new VerificationException(VerificationStatus.INVALID_APP_IDENTIFIER)
      }
      if (this.environment !== environment) {
        throw new VerificationException(VerificationStatus.INVALID_ENVIRONMENT)
      }
    }

    /**
     * Verifies and decodes a signed AppTransaction
     * See {@link https://developer.apple.com/documentation/storekit/apptransaction AppTransaction}
     *
     * @param signedAppTransaction The signed AppTransaction
     * @returns The decoded AppTransaction after validation
     * @throws VerificationException Thrown if the data could not be verified
     */
    async verifyAndDecodeAppTransaction(signedAppTransaction: string): Promise<AppTransaction> {
      const decodedAppTransaction: AppTransaction = await this.verifyJWT(signedAppTransaction, this.appTransactionValidator, t => t.receiptCreationDate === undefined ? new Date() : new Date(t.receiptCreationDate));
      const environment = decodedAppTransaction.receiptType
      if (this.bundleId !== decodedAppTransaction.bundleId || (this.environment === Environment.PRODUCTION && this.appAppleId !== decodedAppTransaction.appAppleId)) {
        throw new VerificationException(VerificationStatus.INVALID_APP_IDENTIFIER)
      }
      if (this.environment !== environment) {
        throw new VerificationException(VerificationStatus.INVALID_ENVIRONMENT)
      }
      return decodedAppTransaction
    }

    /**
     * Verifies and decodes a Retention Messaging API signedPayload
     * See {@link https://developer.apple.com/documentation/retentionmessaging/signedpayload signedPayload}
     *
     * @param signedPayload The payload received by your server
     * @returns The decoded payload after verification
     * @throws VerificationException Thrown if the data could not be verified
     */
    async verifyAndDecodeRealtimeRequest(signedPayload: string): Promise<DecodedRealtimeRequestBody> {
      const decodedRequest: DecodedRealtimeRequestBody = await this.verifyJWT(signedPayload, this.decodedRealtimeRequestBodyValidator, this.extractSignedDate);
      if (this.environment === Environment.PRODUCTION && this.appAppleId !== decodedRequest.appAppleId) {
        throw new VerificationException(VerificationStatus.INVALID_APP_IDENTIFIER)
      }
      if (this.environment !== decodedRequest.environment) {
        throw new VerificationException(VerificationStatus.INVALID_ENVIRONMENT)
      }
      return decodedRequest
    }

    protected async verifyJWT<T>(jwt: string, validator: Validator<T>, signedDateExtractor: (decodedJWT: T) => Date): Promise<T> {
      let certificateChain;
      let decodedJWT
      try {
        decodedJWT = jose.decodeJwt(jwt) as unknown as T
        if (!validator.validate(decodedJWT)) {
          throw new VerificationException(VerificationStatus.FAILURE)
        }
        if (this.environment === Environment.XCODE || this.environment === Environment.LOCAL_TESTING) {
          // Data is not signed by the App Store, and verification should be skipped
          // The environment MUST be checked in the public method calling this
          return decodedJWT
        }
        try {
          const header = jose.decodeProtectedHeader(jwt)
          const chain: string[] = header.x5c ?? []
          if (chain.length != 3) {
            throw new VerificationException(VerificationStatus.INVALID_CHAIN_LENGTH)
          }
          certificateChain = chain.slice(0, 2).map(cert => new X509Certificate(base64ToUint8Array(cert)))
        } catch (error) {
          if (error instanceof Error) {
            throw new VerificationException(VerificationStatus.INVALID_CERTIFICATE, error)
          }
          throw new VerificationException(VerificationStatus.INVALID_CERTIFICATE)
        }
        const effectiveDate = this.enableOnlineChecks ? new Date() : signedDateExtractor(decodedJWT)
        const publicKey = await this.verifyCertificateChain(this.rootCertificates, certificateChain[0], certificateChain[1], effectiveDate);
        await jose.jwtVerify(jwt, publicKey)
        return decodedJWT
      } catch (error) {
        if (error instanceof VerificationException) {
          throw error
        } else if (error instanceof Error) {
          throw new VerificationException(VerificationStatus.VERIFICATION_FAILURE, error)
        }
        throw new VerificationException(VerificationStatus.VERIFICATION_FAILURE)
      }
    }

    protected async verifyCertificateChain(trustedRoots: X509Certificate[], leaf: X509Certificate, intermediate: X509Certificate, effectiveDate: Date): Promise<CryptoKey> {
      let cacheKey = uint8ArrayToBase64(new Uint8Array(leaf.rawData)) + uint8ArrayToBase64(new Uint8Array(intermediate.rawData))
      if (this.enableOnlineChecks) {
        if (cacheKey in this.verifiedPublicKeyCache) {
          if (this.verifiedPublicKeyCache[cacheKey].cacheExpiry > new Date().getTime()) {
            return this.verifiedPublicKeyCache[cacheKey].publicKey
          }
        }
      }

      let publicKey = await this.verifyCertificateChainWithoutCaching(trustedRoots, leaf, intermediate, effectiveDate)

      if (this.enableOnlineChecks) {
        this.verifiedPublicKeyCache[cacheKey] = new CacheValue(publicKey, new Date().getTime() + CACHE_TIME_LIMIT)
        if (Object.keys(this.verifiedPublicKeyCache).length > MAXIMUM_CACHE_SIZE) {
          for (let key in Object.keys(this.verifiedPublicKeyCache)) {
            if (this.verifiedPublicKeyCache[key].cacheExpiry < new Date().getTime()) {
              delete this.verifiedPublicKeyCache[key]
            }
          }
        }
      }
      return publicKey
    }

    protected async verifyCertificateChainWithoutCaching(trustedRoots: X509Certificate[], leaf: X509Certificate, intermediate: X509Certificate, effectiveDate: Date): Promise<CryptoKey> {
      let validity = false
      let rootCert
      for (const root of trustedRoots) {
        try {
          const rootKey = await root.publicKey.export()
          if (await intermediate.verify({ publicKey: rootKey }) && intermediate.issuer === root.subject) {
            validity = true
            rootCert = root
          }
        } catch {
          // Root cert may be invalid or incompatible, continue checking others
        }
      }
      try {
        const intermediateKey = await intermediate.publicKey.export()
        validity = validity && await leaf.verify({ publicKey: intermediateKey }) && leaf.issuer === intermediate.subject
      } catch {
        validity = false
      }
      validity = validity && isCA(intermediate)
      validity = validity && hasExtension(leaf, "1.2.840.113635.100.6.11.1")
      validity = validity && hasExtension(intermediate, "1.2.840.113635.100.6.2.1")
      if (!validity) {
        throw new VerificationException(VerificationStatus.VERIFICATION_FAILURE);
      }
      rootCert = rootCert as X509Certificate
      this.checkDates(leaf, effectiveDate)
      this.checkDates(intermediate, effectiveDate)
      this.checkDates(rootCert, effectiveDate)
      if (this.enableOnlineChecks) {
        await Promise.all([this.checkOCSPStatus(leaf, intermediate), this.checkOCSPStatus(intermediate, rootCert)])
      }
      return await leaf.publicKey.export()
    }
    protected async checkOCSPStatus(cert: X509Certificate, issuer: X509Certificate): Promise<void> {
      const ocspUrl = getOCSPUrl(cert)
      if (ocspUrl === null) {
        throw new VerificationException(VerificationStatus.INVALID_CERTIFICATE)
      }

      const requestBody = await buildOCSPRequest(cert, issuer)

      let response
      try {
        response = await fetch(ocspUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/ocsp-request' },
          body: requestBody
        })
        if (!response.ok) {
          throw new VerificationException(VerificationStatus.RETRYABLE_VERIFICATION_FAILURE)
        }
      } catch (error) {
        if (error instanceof VerificationException) throw error
        throw new VerificationException(VerificationStatus.RETRYABLE_VERIFICATION_FAILURE, error instanceof Error ? error : undefined)
      }

      const responseBytes = new Uint8Array(await response.arrayBuffer())
      const parsed = parseOCSPResponse(responseBytes)

      // Collect candidate signing certs
      const allCerts: X509Certificate[] = [issuer]
      for (const certDer of parsed.certs) {
        allCerts.push(new X509Certificate(certDer))
      }

      // Find signing cert by responder ID
      let signingCert: X509Certificate | null = null
      if (parsed.respIdType === 'key') {
        const keyHashHex = uint8ArrayToHex(parsed.respIdValue)
        for (const c of allCerts) {
          const h = new Uint8Array(await crypto.subtle.digest('SHA-1', getSPKIKeyBytes(c)))
          if (uint8ArrayToHex(h) === keyHashHex) signingCert = c
        }
      } else {
        const respNameHex = uint8ArrayToHex(parsed.respIdValue)
        for (const c of allCerts) {
          if (uint8ArrayToHex(getSubjectNameDER(c)) === respNameHex) signingCert = c
        }
      }
      if (signingCert === null) {
        throw new VerificationException(VerificationStatus.FAILURE)
      }

      // Verify signing cert is issued by issuer
      const issuerKey = await issuer.publicKey.export()
      const signerKey = await signingCert.publicKey.export()
      const signerSPKI = new Uint8Array(await crypto.subtle.exportKey('spki', signerKey) as ArrayBuffer)
      const issuerSPKI = new Uint8Array(await crypto.subtle.exportKey('spki', issuerKey) as ArrayBuffer)

      if (uint8ArrayToHex(signerSPKI) === uint8ArrayToHex(issuerSPKI) && signingCert.subject === issuer.subject) {
        // Directly signed by issuer
      } else if (await signingCert.verify({ publicKey: issuerKey })) {
        // Delegated — check EKU and dates
        if (!hasExtKeyUsage(signingCert, '1.3.6.1.5.5.7.3.9')) {
          throw new VerificationException(VerificationStatus.INVALID_CERTIFICATE)
        }
        this.checkDates(signingCert, new Date())
      } else {
        throw new VerificationException(VerificationStatus.INVALID_CERTIFICATE)
      }

      // Verify response signature
      const sigAlg = SIG_ALG_MAP[parsed.sigAlgOid]
      if (!sigAlg) throw new VerificationException(VerificationStatus.FAILURE)
      const hash = sigAlg.hash.replace('-', '').toUpperCase()
      if (hash !== 'SHA256' && hash !== 'SHA384' && hash !== 'SHA512') {
        throw new VerificationException(VerificationStatus.FAILURE)
      }

      let importAlg: any, verifyAlg: any, sigToVerify = parsed.signature
      if (sigAlg.name === 'ECDSA') {
        importAlg = { name: 'ECDSA', namedCurve: sigAlg.namedCurve }
        verifyAlg = { name: 'ECDSA', hash: sigAlg.hash }
        sigToVerify = ecdsaDerToRaw(parsed.signature, sigAlg.componentSize!)
      } else {
        importAlg = { name: 'RSASSA-PKCS1-v1_5', hash: sigAlg.hash }
        verifyAlg = { name: 'RSASSA-PKCS1-v1_5' }
      }

      const verifyKey = await crypto.subtle.importKey('spki', await crypto.subtle.exportKey('spki', signerKey) as ArrayBuffer, importAlg, false, ['verify'])
      if (!await crypto.subtle.verify(verifyAlg, verifyKey, sigToVerify, parsed.tbsResponseDataTLV)) {
        throw new VerificationException(VerificationStatus.FAILURE)
      }

      // Match CertID and check status
      const issuerNameHash = uint8ArrayToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', getSubjectNameDER(issuer))))
      const issuerKeyHash = uint8ArrayToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', getSPKIKeyBytes(issuer))))
      const certSerial = cert.serialNumber

      for (const sr of parsed.responses) {
        if (sr.certId.alg !== SHA256_OID) continue
        if (sr.certId.nameHash !== issuerNameHash || sr.certId.keyHash !== issuerKeyHash) continue
        const srSerial = sr.certId.serial.replace(/^0+/, '') || '0'
        const ourSerial = certSerial.replace(/^0+/, '') || '0'
        if (srSerial !== ourSerial) continue

        const issueDate = this.parseX509Date(sr.thisUpdate)
        const nextDate = this.parseX509Date(sr.nextUpdate)
        if (sr.status !== 'good' || new Date().getTime() - MAX_SKEW < issueDate.getTime() || nextDate.getTime() < new Date().getTime() + MAX_SKEW) {
          throw new VerificationException(VerificationStatus.FAILURE)
        }
        return
      }
      throw new VerificationException(VerificationStatus.FAILURE)
    }

    private checkDates(cert: X509Certificate, effectiveDate: Date) {
      if (cert.notBefore.getTime() > (effectiveDate.getTime() + MAX_SKEW)||
          cert.notAfter.getTime() < (effectiveDate.getTime() - MAX_SKEW)) {
        throw new VerificationException(VerificationStatus.INVALID_CERTIFICATE)
      }
    }

    private parseX509Date(date: string) {
      return new Date(date.replace(
        /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)$/,
        '$4:$5:$6 $2/$3/$1'
      ));
    }

    private extractSignedDate(decodedJWT: DecodedSignedData): Date {
      return decodedJWT.signedDate === undefined ? new Date() : new Date(decodedJWT.signedDate)
    }
}

export enum VerificationStatus {
  OK,
  VERIFICATION_FAILURE,
  RETRYABLE_VERIFICATION_FAILURE,
  INVALID_APP_IDENTIFIER,
  INVALID_ENVIRONMENT,
  INVALID_CHAIN_LENGTH,
  INVALID_CERTIFICATE,
  FAILURE
}

export class VerificationException extends Error {
  status: VerificationStatus
  cause?: Error

  constructor(status: VerificationStatus, cause?: Error) {
    super();
    this.status = status
    this.cause = cause
  }
}
