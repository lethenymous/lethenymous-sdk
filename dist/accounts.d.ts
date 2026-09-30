import { PublicKey } from "@solana/web3.js";
import type { PoolState, ProtocolConfig, ShieldedState, TreeState } from "./types.js";
export declare function decodePool(data: Uint8Array, address?: PublicKey): PoolState;
export declare function decodeShieldedState(data: Uint8Array): ShieldedState;
export declare function decodeProtocolConfig(data: Uint8Array): ProtocolConfig;
export declare function decodeTreeState(data: Uint8Array): TreeState;
