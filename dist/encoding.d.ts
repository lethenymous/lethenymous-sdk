import { PublicKey } from "@solana/web3.js";
export declare const PROGRAM_ID: PublicKey;
export declare const SYSTEM_PROGRAM_ID: PublicKey;
export declare const TOKEN_PROGRAM_ID: PublicKey;
export declare function discriminator(name: string): Buffer;
export declare function accountDiscriminator(name: string): Buffer;
export declare function concat(...parts: Uint8Array[]): Buffer;
export declare function u16(value: number): Buffer;
export declare function u64(value: bigint): Buffer;
export declare function vec(bytes: Uint8Array): Buffer;
export declare function u32(value: number): Buffer;
export declare function pubkey(value: PublicKey): Buffer;
export declare function bytes32(value: Uint8Array): Buffer;
export declare function bool(value: boolean): Buffer;
export declare function enumByte(value: number): Buffer;
export declare class Reader {
    private readonly data;
    private offset;
    constructor(data: Uint8Array);
    bytes(length: number): Buffer;
    pubkey(): PublicKey;
    u8(): number;
    u16(): number;
    u64(): bigint;
    rest(): number;
}
