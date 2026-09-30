import { sha256 } from "@noble/hashes/sha256";
import { PublicKey } from "@solana/web3.js";
export const PROGRAM_ID = new PublicKey("ZkCP47fAJJREdXNKSBvTsgJAuLoTKepgk6opmqsHobm");
export const SYSTEM_PROGRAM_ID = new PublicKey("11111111111111111111111111111111");
export const TOKEN_PROGRAM_ID = new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
export function discriminator(name) {
    return Buffer.from(sha256(new TextEncoder().encode(`global:${name}`)).subarray(0, 8));
}
export function accountDiscriminator(name) {
    return Buffer.from(sha256(new TextEncoder().encode(`account:${name}`)).subarray(0, 8));
}
export function concat(...parts) { return Buffer.concat(parts.map(Buffer.from)); }
export function u16(value) { if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff)
    throw new Error("Invalid u16"); const b = Buffer.alloc(2); b.writeUInt16LE(value); return b; }
export function u64(value) { if (typeof value !== "bigint" || value < 0n || value > 0xffffffffffffffffn)
    throw new Error("u64 requires a bigint in range"); const b = Buffer.alloc(8); b.writeBigUInt64LE(value); return b; }
export function vec(bytes) { return concat(u32(bytes.length), bytes); }
export function u32(value) { if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff)
    throw new Error("Invalid u32"); const b = Buffer.alloc(4); b.writeUInt32LE(value); return b; }
export function pubkey(value) { return Buffer.from(value.toBytes()); }
export function bytes32(value) {
    if (value.length !== 32)
        throw new Error("Expected exactly 32 bytes");
    return Buffer.from(value);
}
export function bool(value) { return Buffer.from([value ? 1 : 0]); }
export function enumByte(value) { if (!Number.isSafeInteger(value) || value < 0 || value > 255)
    throw new Error("Invalid enum"); return Buffer.from([value]); }
export class Reader {
    data;
    offset = 0;
    constructor(data) {
        this.data = data;
    }
    bytes(length) { const out = Buffer.from(this.data.subarray(this.offset, this.offset + length)); this.offset += length; return out; }
    pubkey() { return new PublicKey(this.bytes(32)); }
    u8() { return this.bytes(1)[0]; }
    u16() { return this.bytes(2).readUInt16LE(); }
    u64() { return this.bytes(8).readBigUInt64LE(); }
    rest() { return this.data.length - this.offset; }
}
