import { PublicKey, type Connection } from "@solana/web3.js";
/** Only a null finalized response means absent. Unexpected state is unknown,
 * never proof that a note is unspent. Addresses are derived here, not supplied
 * by callers. Used for both issued-output and consumed-input recovery. */
export declare function readCanonicalSpentStates(connection: Pick<Connection, "getMultipleAccountsInfo">, programId: PublicKey, pool: PublicKey, nullifiers: Uint8Array[]): Promise<boolean[]>;
