import { PublicKey, type Connection } from "@solana/web3.js";
import { accountDiscriminator } from "./encoding.js";
import { pda } from "./pda.js";

/** Only a null finalized response means absent. Unexpected state is unknown,
 * never proof that a note is unspent. Addresses are derived here, not supplied
 * by callers. Used for both issued-output and consumed-input recovery. */
export async function readCanonicalSpentStates(connection: Pick<Connection, "getMultipleAccountsInfo">, programId: PublicKey, pool: PublicKey, nullifiers: Uint8Array[]): Promise<boolean[]> {
  const result: boolean[] = [], discriminator = accountDiscriminator("SpentNullifier");
  for (let offset = 0; offset < nullifiers.length; offset += 100) {
    const batch = nullifiers.slice(offset, offset + 100);
    if (batch.some(nf => nf.length !== 32)) throw new Error("Invalid spent-nullifier identity");
    const addresses = batch.map(nf => pda.spent(pool, nf, programId)[0]);
    const accounts = await connection.getMultipleAccountsInfo(addresses, "finalized");
    if (accounts.length !== batch.length) throw new Error("RPC returned an incomplete spent-nullifier response");
    for (let i = 0; i < batch.length; i++) {
      const account = accounts[i];
      if (account === null) { result.push(false); continue; }
      if (!account || account.executable !== false || !account.owner.equals(programId) || !Buffer.isBuffer(account.data) || account.data.length !== 73 || !account.data.subarray(0, 8).equals(discriminator) || !account.data.subarray(8, 40).equals(pool.toBuffer()) || !account.data.subarray(40, 72).equals(Buffer.from(batch[i])) || account.data[72] !== 1) throw new Error("Invalid canonical spent-nullifier account");
      result.push(true);
    }
  }
  return result;
}
