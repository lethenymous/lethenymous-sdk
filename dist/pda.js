import { PublicKey } from "@solana/web3.js";
import { PROGRAM_ID } from "./encoding.js";
export const pda = {
    pool: (a, b, feeBps, programId = PROGRAM_ID) => PublicKey.findProgramAddressSync([Buffer.from("pool"), a.toBuffer(), b.toBuffer(), u16le(feeBps)], programId),
    vaultA: (pool, programId = PROGRAM_ID) => find("vault-a", pool, programId),
    vaultB: (pool, programId = PROGRAM_ID) => find("vault-b", pool, programId),
    protocolFeeA: (pool, programId = PROGRAM_ID) => find("protocol-fee-a", pool, programId),
    protocolFeeB: (pool, programId = PROGRAM_ID) => find("protocol-fee-b", pool, programId),
    creatorFeeA: (pool, programId = PROGRAM_ID) => find("creator-fee-a", pool, programId),
    creatorFeeB: (pool, programId = PROGRAM_ID) => find("creator-fee-b", pool, programId),
    lpMint: (pool, programId = PROGRAM_ID) => find("lp", pool, programId),
    lpLock: (pool, programId = PROGRAM_ID) => find("lp-lock", pool, programId),
    shielded: (pool, programId = PROGRAM_ID) => find("shielded", pool, programId),
    tree: (pool, programId = PROGRAM_ID) => find("tree", pool, programId),
    custodyA: (pool, programId = PROGRAM_ID) => find("custody-a", pool, programId),
    custodyB: (pool, programId = PROGRAM_ID) => find("custody-b", pool, programId),
    spent: (pool, nullifier, programId = PROGRAM_ID) => PublicKey.findProgramAddressSync([Buffer.from("spent"), pool.toBuffer(), Buffer.from(nullifier)], programId),
    protocolConfig: (programId = PROGRAM_ID) => PublicKey.findProgramAddressSync([Buffer.from("protocol-config")], programId),
};
function find(seed, pool, programId) { return PublicKey.findProgramAddressSync([Buffer.from(seed), pool.toBuffer()], programId); }
function u16le(v) { const b = Buffer.alloc(2); b.writeUInt16LE(v); return b; }
