import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { poseidon2, poseidon3, poseidon9 } from "poseidon-lite";
import { PublicKey } from "@solana/web3.js";
const DOMAIN = 0x5a4b43504d4d0003n;
const OWNER_DOMAIN = 0x5a4b43504d4f0003n;
const NULLIFIER_DOMAIN = 0x5a4b43504d4e0003n;
const NOTE_VERSION = 2;
const PAYLOAD_VERSION = 1;
const AAD = Buffer.from("zkcpmm-v2/note-payload");
export const NOTE_PLAINTEXT_LENGTH = 145;
export const NOTE_PAYLOAD_LENGTH = 1 + 24 + NOTE_PLAINTEXT_LENGTH + 16;
const zero32 = () => new Uint8Array(32);
const be = (n) => { const b = Buffer.alloc(32); b.writeBigUInt64BE(n, 24); return b; };
const big = (b) => BigInt(`0x${Buffer.from(b).toString("hex")}`);
export function hash2(a, b) {
    const n = poseidon2([big(a), big(b)]);
    return Buffer.from(n.toString(16).padStart(64, "0"), "hex");
}
function limb(b) {
    const out = zero32();
    out.set(b.subarray(0, 16), 16);
    return out;
}
export function keyHierarchy(seed) {
    const spendSecret = hkdf(sha256, seed, Buffer.from("zkcpmm-v2/key-hierarchy"), Buffer.from("spend"), 32);
    const viewKey = hkdf(sha256, seed, Buffer.from("zkcpmm-v2/key-hierarchy"), Buffer.from("view"), 32);
    const storageKey = hkdf(sha256, seed, Buffer.from("zkcpmm-v2/key-hierarchy"), Buffer.from("note-store/v1"), 32);
    return { spendSecret, viewKey, storageKey };
}
export function noteStoreKey(seed) {
    return keyHierarchy(seed).storageKey;
}
function poseidonN(values, width) {
    const n = (width === 3 ? poseidon3 : poseidon9)(values.map(big));
    return Buffer.from(n.toString(16).padStart(64, "0"), "hex");
}
function fold(values) {
    return values.reduce((a, b) => hash2(a, b));
}
export function ownerCommitment(spend) {
    if (spend.length !== 32)
        throw new Error("Spend secret must be 32 bytes");
    return poseidonN([be(OWNER_DOMAIN), limb(spend), limb(spend.subarray(16))], 3);
}
export function noteCommitment(pool, asset, amount, owner, randomness) {
    if (owner.length !== 32 || randomness.length !== 32)
        throw new Error("Note fields must be 32 bytes");
    const p = pool.toBytes();
    const a = asset.toBytes();
    return fold([be(DOMAIN), limb(p), limb(p.subarray(16)), limb(a), limb(a.subarray(16)), be(amount), owner, limb(randomness), limb(randomness.subarray(16))]);
}
export function nullifier(pool, asset, spend, randomness) {
    if (spend.length !== 32 || randomness.length !== 32)
        throw new Error("Nullifier fields must be 32 bytes");
    const p = pool.toBytes();
    const a = asset.toBytes();
    return poseidonN([be(NULLIFIER_DOMAIN), limb(p), limb(p.subarray(16)), limb(a), limb(a.subarray(16)), limb(spend), limb(spend.subarray(16)), limb(randomness), limb(randomness.subarray(16))], 9);
}
export function encodeNote(pool, asset, amount, owner, randomness) {
    if (owner.length !== 32 || randomness.length !== 32 || amount < 0n || amount > 0xffffffffffffffffn)
        throw new Error("Invalid note");
    const b = Buffer.alloc(NOTE_PLAINTEXT_LENGTH);
    b[0] = NOTE_VERSION;
    be(DOMAIN).subarray(24).copy(b, 1);
    Buffer.from(pool.toBytes()).copy(b, 9);
    Buffer.from(asset.toBytes()).copy(b, 41);
    be(amount).subarray(24).copy(b, 73);
    Buffer.from(owner).copy(b, 81);
    Buffer.from(randomness).copy(b, 113);
    return b;
}
export function encryptNote(note, viewKey, pool, asset, commitment) {
    if (note.length !== NOTE_PLAINTEXT_LENGTH || viewKey.length !== 32 || commitment.length !== 32)
        throw new Error("Invalid note payload");
    const nonce = cryptoRandom(24);
    const aad = Buffer.concat([AAD, pool.toBuffer(), asset.toBuffer(), Buffer.from(commitment)]);
    const cipher = xchacha20poly1305(viewKey, nonce, aad).encrypt(note);
    const payload = Buffer.concat([Buffer.from([PAYLOAD_VERSION]), nonce, Buffer.from(cipher)]);
    if (payload.length !== NOTE_PAYLOAD_LENGTH)
        throw new Error("Invalid encrypted note length");
    return payload;
}
export function decryptNotePayload(payload, viewKey, pool, asset, commitment) {
    if (payload.length !== NOTE_PAYLOAD_LENGTH || payload[0] !== PAYLOAD_VERSION)
        throw new Error("Invalid encrypted note payload");
    const aad = Buffer.concat([AAD, pool.toBuffer(), asset.toBuffer(), Buffer.from(commitment)]);
    const plaintext = Buffer.from(xchacha20poly1305(viewKey, payload.subarray(1, 25), aad).decrypt(payload.subarray(25)));
    if (plaintext.length !== NOTE_PLAINTEXT_LENGTH || plaintext[0] !== NOTE_VERSION)
        throw new Error("Invalid note plaintext");
    const decodedPool = new PublicKey(plaintext.subarray(9, 41));
    const decodedAsset = new PublicKey(plaintext.subarray(41, 73));
    const amount = plaintext.readBigUInt64BE(73);
    const ownerCommitmentValue = plaintext.subarray(81, 113);
    const randomness = plaintext.subarray(113, 145);
    if (!decodedPool.equals(pool) || !decodedAsset.equals(asset))
        throw new Error("Note payload identity mismatch");
    if (!Buffer.from(noteCommitment(pool, asset, amount, ownerCommitmentValue, randomness)).equals(Buffer.from(commitment)))
        throw new Error("Note commitment mismatch");
    return { pool: decodedPool, asset: decodedAsset, amount, ownerCommitment: Uint8Array.from(ownerCommitmentValue), randomness: Uint8Array.from(randomness) };
}
export function cryptoRandom(length) {
    if (!Number.isSafeInteger(length) || length <= 0)
        throw new Error("Invalid randomness length");
    if (!globalThis.crypto)
        throw new Error("Secure randomness unavailable");
    const out = new Uint8Array(length);
    globalThis.crypto.getRandomValues(out);
    return out;
}
