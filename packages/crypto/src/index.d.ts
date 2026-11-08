export declare const FORMAT_VERSION: 1;
export declare const READABLE_FORMAT_VERSIONS: readonly number[];
export declare const PBKDF2_ITERATIONS: number;

export declare class FormatError extends Error {
    readonly name: 'FormatError';
    readonly code: 'fingerprint_mismatch';
    constructor(code: string, message: string);
}

export declare function parseFormatVersion(value: string | number | null | undefined): number;
export declare function isReadableFormat(version: number): boolean;

export declare function bufToBase64(buf: ArrayBuffer | Uint8Array): string;
export declare function base64ToBuf(b64: string): ArrayBuffer;

export interface FileEntry {
    filename: string;
    mimetype?: string;
    data: ArrayBuffer | Uint8Array;
}
export declare function textEnvelope(content: string, format?: string): string;
export declare function filesEnvelope(files: FileEntry[]): string;
export declare function sanitizeFilename(name: unknown): string;

export interface RevealAuthorization {
    token: string;
    tokenHash: string;
}
export interface RevealFragment {
    version: number;
    key: string;
    token: string;
}
export interface SubmitFragment {
    version: number;
    fingerprint: string;
}
export declare function revealTokenHash(token: string): Promise<string>;
export declare function generateRevealAuthorization(): Promise<RevealAuthorization>;
export declare function revealFragment(key: string, token: string): string;
export declare function parseRevealFragment(fragment: string, allowLegacy?: boolean): RevealFragment;
export declare function submitFragment(fingerprint: string): string;
export declare function parseSubmitFragment(fragment: string): SubmitFragment;

export interface EncryptedContent {
    ciphertext: string;
    iv: string;
    salt: string;
}
export declare function generateKey(): Promise<string>;
export declare function encryptContent(
    plaintext: string,
    keyB64: string | null | undefined,
    password?: string,
): Promise<EncryptedContent>;
export declare function decryptContent(
    ciphertextB64: string,
    ivB64: string,
    keyB64: string | null | undefined,
    password?: string,
    saltB64?: string,
): Promise<string>;

export interface RequestKeyPair {
    seedB64: string;
    publicKeyB64: string;
    fingerprintB64: string;
}
export interface SealedContent {
    ciphertext: string;
    iv: string;
    encapsulated_key: string;
}
export interface WrappedKey {
    wrappedKey: string;
    wrappedKeyIv: string;
    salt: string;
}
export declare function generateRequestKeyPair(): Promise<RequestKeyPair>;
export declare function sealForRecipient(
    plaintext: string,
    publicKeyB64: string,
    fingerprintB64: string,
): Promise<SealedContent>;
export declare function openFromSender(data: SealedContent, seedB64: string): Promise<string>;
export declare function wrapPrivateKey(seedB64: string, password: string): Promise<WrappedKey>;
export declare function unwrapPrivateKey(
    wrappedKeyB64: string,
    wrappedKeyIvB64: string,
    password: string,
    saltB64: string,
): Promise<string>;
