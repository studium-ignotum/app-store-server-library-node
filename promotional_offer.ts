// Copyright (c) 2023 Apple Inc. Licensed under MIT License.

function pemToArrayBuffer(pem: string): ArrayBuffer {
    const b64 = pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s/g, '')
    const binary = atob(b64)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
    return bytes.buffer
}

export class PromotionalOfferSignatureCreator {

    private signingKey: string;
    private keyId: string;
    private bundleId: string;

    public constructor(signingKey: string, keyId: string, bundleId: string) {
        this.signingKey = signingKey;
        this.keyId = keyId
        this.bundleId = bundleId
    }

    /**
     * Create a promotional offer signature
     *
     * {@link https://developer.apple.com/documentation/storekit/in-app_purchase/original_api_for_in-app_purchase/subscriptions_and_offers/generating_a_signature_for_promotional_offers Generating a signature for promotional offers}
     * @param productIdentifier The subscription product identifier
     * @param subscriptionOfferID The subscription discount identifier
     * @param appAccountToken An optional string value that you define; may be an empty string
     * @param nonce A one-time UUID value that your server generates. Generate a new nonce for every signature.
     * @param timestamp A timestamp your server generates in UNIX time format, in milliseconds. The timestamp keeps the offer active for 24 hours.
     * @return The Base64 encoded signature
     */
    public async createSignature(productIdentifier: string, subscriptionOfferID: string, appAccountToken: string, nonce: string, timestamp: number): Promise<string> {
        const payload = this.bundleId + '\u2063' +
            this.keyId + '\u2063' +
            productIdentifier + '\u2063' +
            subscriptionOfferID + '\u2063' +
            appAccountToken.toLowerCase()  + '\u2063'+
            nonce.toLowerCase() + '\u2063' +
            timestamp;
        const keyData = pemToArrayBuffer(this.signingKey)
        const privateKey = await crypto.subtle.importKey(
            'pkcs8', keyData,
            { name: 'ECDSA', namedCurve: 'P-256' },
            false, ['sign']
        )
        const encoder = new TextEncoder()
        const data = encoder.encode(payload)
        const signature = await crypto.subtle.sign(
            { name: 'ECDSA', hash: { name: 'SHA-256' } },
            privateKey,
            data
        )
        const sigBytes = new Uint8Array(signature)
        let binary = ''
        for (let i = 0; i < sigBytes.length; i++) binary += String.fromCharCode(sigBytes[i])
        return btoa(binary)
    }
}
