// Copyright (c) 2023 Apple Inc. Licensed under MIT License.

const IN_APP_TYPE_ID = 17;
const TRANSACTION_IDENTIFIER_TYPE_ID = 1703;
const ORIGINAL_TRANSACTION_IDENTIFIER_TYPE_ID = 1705;

// --- Minimal ASN.1 DER parser (replaces jsrsasign ASN1HEX) ---

function hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2)
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16)
    }
    return bytes
}

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

function base64ToHex(b64: string): string {
    const binary = atob(b64)
    let hex = ''
    for (let i = 0; i < binary.length; i++) {
        hex += binary.charCodeAt(i).toString(16).padStart(2, '0')
    }
    return hex
}

function hexToString(hex: string): string {
    const bytes = hexToBytes(hex)
    let str = ''
    for (let i = 0; i < bytes.length; i++) {
        str += String.fromCharCode(bytes[i])
    }
    return str
}

/**
 * Get the length byte 'L' hex string at position idx in the hex string s.
 */
function getL(s: string, idx: number): string {
    const byte = s.substring(idx + 2, idx + 4)
    return byte
}

/**
 * Get the byte length of the length field at position idx.
 * Returns -1 for indefinite length (0x80).
 */
function getLblen(s: string, idx: number): number {
    const firstByte = parseInt(s.substring(idx + 2, idx + 4), 16)
    if (firstByte === 0x80) return -1 // indefinite length
    if (firstByte < 0x80) return 1
    return 1 + (firstByte & 0x7f)
}

/**
 * Get the value byte length at position idx.
 */
function getVblen(s: string, idx: number): number {
    const firstByte = parseInt(s.substring(idx + 2, idx + 4), 16)
    if (firstByte === 0x80) {
        // Indefinite length — round up to remaining length
        return (s.length - idx) / 2
    }
    if (firstByte < 0x80) return firstByte
    const numLenBytes = firstByte & 0x7f
    let length = 0
    for (let i = 0; i < numLenBytes; i++) {
        length = (length * 256) + parseInt(s.substring(idx + 4 + i * 2, idx + 6 + i * 2), 16)
    }
    return length
}

/**
 * Get the value hex string at position idx.
 */
function getV(s: string, idx: number): string {
    const lbytes = getLblen(s, idx)
    if (lbytes === -1) {
        // Indefinite length
        const vStart = idx + 4
        return s.substring(vStart)
    }
    const vLen = getVblen(s, idx)
    const vStart = idx + 2 + lbytes * 2
    return s.substring(vStart, vStart + vLen * 2)
}

/**
 * Navigate ASN.1 tree by index path and get the value hex string.
 * Returns the value at the given path, or throws if not found.
 */
function getVbyList(s: string, startIdx: number, path: number[]): string | null {
    try {
        let currentIdx = startIdx
        for (let p = 0; p < path.length; p++) {
            // Skip the tag byte
            const lbytes = getLblen(s, currentIdx)
            if (lbytes === -1) {
                // indefinite length
                currentIdx = currentIdx + 4 // skip tag + 0x80
            } else {
                currentIdx = currentIdx + 2 + lbytes * 2 // skip tag + length bytes
            }

            // Navigate to the nth child
            for (let childIdx = 0; childIdx < path[p]; childIdx++) {
                const childLbytes = getLblen(s, currentIdx)
                if (childLbytes === -1) {
                    // Can't easily skip indefinite length children
                    return null
                }
                const childVlen = getVblen(s, currentIdx)
                currentIdx = currentIdx + 2 + childLbytes * 2 + childVlen * 2
                if (currentIdx >= s.length) return null
            }
        }
        if (currentIdx >= s.length) return null
        return getV(s, currentIdx)
    } catch {
        return null
    }
}

// --- End ASN.1 parser ---

export class ReceiptUtility {

    /**
     * Extracts a transaction id from an encoded App Receipt. Throws if the receipt does not match the expected format.
     * *NO validation* is performed on the receipt, and any data returned should only be used to call the App Store Server API.
     * @param appReceipt The unmodified app receipt
     * @returns A transaction id from the array of in-app purchases, null if the receipt contains no in-app purchases
     */
    extractTransactionIdFromAppReceipt(appReceipt: string): string | null {
        // Xcode receipts use indefinite length encoding, not supported by all parsers
        // Indefinite length encoding is only entered, but never left during parsing for receipts
        // We therefore round up indefinite length encoding to be the remaining length
        // Note: The custom getVblen/getLblen functions above already handle indefinite length (0x80)
        try {
            let receiptInfo = getVbyList(base64ToHex(appReceipt), 0, [1, 0, 2, 1, 0]) as string
            if (receiptInfo.length > 2 && receiptInfo.startsWith('04')) {
                // We are still in an Octet String, Xcode wraps with an extra Octet, decode it here
                receiptInfo = getV(receiptInfo, 0)
            }
            let index = 0;
            while(getVbyList(receiptInfo, 0, [index, 0])) {
                const val = getVbyList(receiptInfo, 0, [index, 0]) as string
                if (IN_APP_TYPE_ID === parseInt(val, 16)) {
                    const inAppInfo = getVbyList(receiptInfo, 0, [index, 2]) as string
                    let inAppIndex = 0;
                    while(getVbyList(inAppInfo, 0, [inAppIndex, 0])) {
                        const val = getVbyList(inAppInfo, 0, [inAppIndex, 0]) as string
                        if (TRANSACTION_IDENTIFIER_TYPE_ID === parseInt(val, 16) || ORIGINAL_TRANSACTION_IDENTIFIER_TYPE_ID === parseInt(val, 16)) {
                            const transactionIdUTF8String = getVbyList(inAppInfo, 0, [inAppIndex, 2]) as string
                            const transactionId = getVbyList(transactionIdUTF8String, 0, []) as string
                            return hexToString(transactionId)
                        }
                        inAppIndex = inAppIndex + 1
                    }
                }
                index = index + 1
            }
            return null
        } catch {
            return null
        }
    }

    /**
     * Extracts a transaction id from an encoded transactional receipt. Throws if the receipt does not match the expected format.
     * *NO validation* is performed on the receipt, and any data returned should only be used to call the App Store Server API.
     * @param transactionReceipt The unmodified transactionReceipt
     * @return A transaction id, or null if no transactionId is found in the receipt
     */
    extractTransactionIdFromTransactionReceipt(transactionReceipt: string): string | null {
        const topLevel = atob(transactionReceipt)
        const topLevelRegex = /"purchase-info"\s+=\s+"([a-zA-Z0-9+/=]+)";/
        const topLevelMatchResult = topLevel.match(topLevelRegex)
        if (!topLevelMatchResult || topLevelMatchResult?.length !== 2) {
            return null
        }

        const purchaseInfo = atob(topLevelMatchResult[1])
        const purchaseInfoRegex = /"transaction-id"\s+=\s+"([a-zA-Z0-9+/=]+)";/
        const purchaseInfoMatchResult = purchaseInfo.match(purchaseInfoRegex)
        if (!purchaseInfoMatchResult || purchaseInfoMatchResult?.length !== 2) {
            return null
        }
        return purchaseInfoMatchResult[1]
    }
}
