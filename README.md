# Apple App Store Server Library — Workers Fork

Fork of [`@apple/app-store-server-library-node`](https://github.com/apple/app-store-server-library-node) (v3.0.0), rewritten to run natively on **Cloudflare Workers** and any WebCrypto-compatible runtime.

Covers the [App Store Server API](https://developer.apple.com/documentation/appstoreserverapi), [App Store Server Notifications V2](https://developer.apple.com/documentation/appstoreservernotifications), and [Retention Messaging API](https://developer.apple.com/documentation/retentionmessaging).

## What changed from upstream

| Upstream (Node.js) | This fork (Workers) |
|---|---|
| `jsonwebtoken` | `jose` |
| `jsrsasign` (X509, ASN1HEX, OCSP) | `@peculiar/x509` + manual DER parser |
| `crypto` (X509Certificate, KeyObject, createHash, verify) | `@peculiar/x509` + `crypto.subtle` |
| `node-fetch` | native `fetch` |
| `Buffer` | `Uint8Array` / `atob` / `btoa` |
| `base64url` | manual base64url |

OCSP revocation checking is fully implemented using manual DER encoding/decoding and `crypto.subtle` for signature verification — no Node.js crypto dependencies.

### Production dependencies

```
jose              ^5.9.0
@peculiar/x509    ^1.12.0
```

Zero Node.js-specific dependencies. Both packages work on Workers, Deno, Bun, and browsers.

## Installation

```bash
# npm
npm install @studium-ignotum/app-store-server-library

# yarn
yarn add @studium-ignotum/app-store-server-library

# pnpm
pnpm add @studium-ignotum/app-store-server-library
```

Or install directly from GitHub:

```bash
# npm
npm install github:studium-ignotum/app-store-server-library-node

# yarn
yarn add studium-ignotum/app-store-server-library-node

# pnpm
pnpm add github:studium-ignotum/app-store-server-library-node
```

Requires a runtime with Web Crypto API (`crypto.subtle`) and native `fetch`.

## Usage

### API Client

```typescript
import { AppStoreServerAPIClient, Environment } from "@studium-ignotum/app-store-server-library"

const client = new AppStoreServerAPIClient(
  encodedKey, keyId, issuerId, bundleId, Environment.SANDBOX
)

const response = await client.requestTestNotification()
```

### Verify Signed Data (JWS)

```typescript
import { SignedDataVerifier, Environment } from "@studium-ignotum/app-store-server-library"

const rootCAs: Uint8Array[] = [appleRootG3DER]  // DER-encoded Apple root certificates
const verifier = new SignedDataVerifier(rootCAs, true, Environment.PRODUCTION, bundleId, appAppleId)

const notification = await verifier.verifyAndDecodeNotification(signedPayload)
```

> Constructor accepts `Uint8Array[]` (not `Buffer[]`). `Buffer` still works at runtime since it extends `Uint8Array`.

### Receipt Utility

```typescript
import { ReceiptUtility } from "@studium-ignotum/app-store-server-library"

const receiptUtil = new ReceiptUtility()
const transactionId = receiptUtil.extractTransactionIdFromAppReceipt(appReceipt)
```

### Promotional Offer Signature

```typescript
import { PromotionalOfferSignatureCreator } from "@studium-ignotum/app-store-server-library"

const creator = new PromotionalOfferSignatureCreator(encodedKey, keyId, bundleId)
const signature = await creator.createSignature(productId, offerId, appAccountToken, nonce, timestamp)
```

> `createSignature` is now **async** (returns `Promise<string>`).

### Cloudflare Workers Example

```typescript
import { AppStoreServerAPIClient, SignedDataVerifier, Environment } from "@studium-ignotum/app-store-server-library"

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const verifier = new SignedDataVerifier(
      [base64ToUint8Array(env.APPLE_ROOT_CA_G3)],
      true,
      Environment.PRODUCTION,
      env.BUNDLE_ID,
      Number(env.APP_APPLE_ID)
    )

    const { signedPayload } = await request.json<{ signedPayload: string }>()
    const notification = await verifier.verifyAndDecodeNotification(signedPayload)

    return Response.json({ type: notification.notificationType })
  }
}
```

## API Changes from Upstream

| Method / Constructor | Change |
|---|---|
| `new SignedDataVerifier(certs, ...)` | `certs` type: `Buffer[]` → `Uint8Array[]` |
| `verifyCertificateChain(...)` | Returns `Promise<CryptoKey>` instead of `Promise<KeyObject>` |
| `PromotionalOfferSignatureCreator.createSignature(...)` | Now **async** — returns `Promise<string>` |
| `PromotionalOfferV2SignatureCreator.createSignature(...)` | Now **async** — returns `Promise<string>` |
| `IntroductoryOfferEligibilitySignatureCreator.createSignature(...)` | Now **async** — returns `Promise<string>` |
| `AdvancedCommerceInAppSignatureCreator.createSignature(...)` | Now **async** — returns `Promise<string>` |
| `AppStoreServerAPIClient.uploadImage(id, image)` | `image` type: `Buffer` → `Uint8Array` |

All other public APIs remain unchanged.

## Obtaining Apple Root Certificates

Download the root certificates from the [Apple PKI](https://www.apple.com/certificateauthority/) site (Apple Root Certificates section). Store them as DER-encoded `Uint8Array` values and pass to `SignedDataVerifier`.

## License

MIT — see [LICENSE.txt](LICENSE.txt). Original library by Apple Inc.
