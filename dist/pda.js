import { PublicKey } from "@solana/web3.js";
import { PROGRAM_ID, u64 } from "./encoding.js";
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
    tree: (pool, generationOrProgram = 0n, programId = PROGRAM_ID) => {
        const generation = generationOrProgram instanceof PublicKey ? 0n : generationOrProgram;
        const program = generationOrProgram instanceof PublicKey ? generationOrProgram : programId;
        if (generation === 0n)
            return find("tree", pool, program);
        return PublicKey.findProgramAddressSync([Buffer.from("tree"), pool.toBuffer(), u64(generation)], program);
    },
    custodyA: (pool, programId = PROGRAM_ID) => find("custody-a", pool, programId),
    pageDirectory: (pool, generation, programId = PROGRAM_ID) => PublicKey.findProgramAddressSync([Buffer.from("page-dir"), pool.toBuffer(), u64(generation)], programId),
    leafPage: (pool, generation, pageIndex, programId = PROGRAM_ID) => {
        if (!Number.isInteger(pageIndex) || pageIndex < 0 || pageIndex >= 16)
            throw new Error("Page index must be 0..15");
        return PublicKey.findProgramAddressSync([Buffer.from("leaf-page"), pool.toBuffer(), u64(generation), Buffer.from([pageIndex])], programId);
    },
    custodyB: (pool, programId = PROGRAM_ID) => find("custody-b", pool, programId),
    spent: (pool, nullifier, programId = PROGRAM_ID) => PublicKey.findProgramAddressSync([Buffer.from("spent"), pool.toBuffer(), Buffer.from(nullifier)], programId),
    protocolConfig: (programId = PROGRAM_ID) => PublicKey.findProgramAddressSync([Buffer.from("protocol-config")], programId),
};
function find(seed, pool, programId) { return PublicKey.findProgramAddressSync([Buffer.from(seed), pool.toBuffer()], programId); }
function u16le(v) { const b = Buffer.alloc(2); b.writeUInt16LE(v); return b; }
