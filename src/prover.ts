import { createHash } from "node:crypto";
import { realpath, stat } from "node:fs/promises";
import { spawn } from "node:child_process";
import { platform, arch } from "node:process";
import { dirname } from "node:path";
import type { MerkleWitness, PrivateSwapProverInput, Prover, UnshieldProverInput } from "./types.js";

const hex = (value: Uint8Array) => Buffer.from(value).toString("hex");
const decimal = (value: bigint) => value.toString(10);
const MAX_U64 = 0xffffffffffffffffn;
export const BN254_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const PROVER_VERSION = "production-prover 0.2.0 ipc-v1";
const PROVER_OUTPUT_MAGIC = Buffer.from("ZKCP");
const PRIVATE_PROVER_SHA256_BY_TARGET: Record<string, string> = {
  // This digest is updated only when the authenticated release binary is built.
  "darwin-arm64": "1772e91b6e6048e90eafee865e06097ebd15cf319a89263d4a0d6e8f2eca2eac",
};

export const PRODUCTION_ARTIFACT_SHA256 = {
  privateSwapPk: "26f9aaa5ff0924bc5c1d4a6fc618f70147d4f8b6d76acdfca3eabbd704cf51f5",
  unshieldPk: "156b0759e8819cb529c59249fbef6e075651655c8f8361f97616a8a1fc981563",
} as const;

const PRODUCTION_ARTIFACT_SIZE = { privateSwapPk: 2_829_872, unshieldPk: 1_409_808 } as const;

const requireBytes32 = (value: Uint8Array, label: string) => {
  if (value.length !== 32) throw new Error(`${label} must be 32 bytes`);
  return value;
};

const field = (value: Uint8Array | bigint): Buffer => {
  const number = typeof value === "bigint" ? value : BigInt(`0x${hex(requireBytes32(value, "field"))}`);
  if (number < 0n || number >= BN254_MODULUS) throw new Error("Noncanonical BN254 field value");
  const output = Buffer.alloc(32);
  let current = number;
  for (let index = 31; index >= 0; index--) { output[index] = Number(current & 255n); current >>= 8n; }
  return output;
};

const u64Field = (value: bigint): Buffer => {
  if (value < 0n || value > MAX_U64) throw new Error("Invalid u64 public input");
  return field(value);
};

const limb = (value: Uint8Array): Buffer => {
  if (value.length < 16) throw new Error("Public-key limb must be at least 16 bytes");
  return Buffer.concat([Buffer.alloc(16), Buffer.from(value.subarray(0, 16))]);
};

export function encodeUnshieldPublicInputs(input: Pick<UnshieldProverInput, "pool" | "asset" | "root" | "nullifier" | "amount" | "recipient">): Uint8Array {
  return Buffer.concat([
    u64Field(0x5a4b43504d4d0003n), limb(input.pool.toBytes()), limb(input.pool.toBytes().subarray(16)),
    limb(input.asset.toBytes()), limb(input.asset.toBytes().subarray(16)), field(input.root), field(input.nullifier),
    u64Field(input.amount), limb(input.recipient.toBytes()), limb(input.recipient.toBytes().subarray(16)),
  ]);
}

export function encodePrivateSwapPublicInputs(input: Pick<PrivateSwapProverInput, "pool" | "assetIn" | "assetOut" | "root" | "rootSequence" | "generation" | "nullifier" | "reserveIn" | "reserveOut" | "feeBps" | "amountIn" | "amountOut" | "changeAmount" | "changeCommitment" | "outputCommitment" | "direction" | "swapNonce">): Uint8Array {
  if (!Number.isSafeInteger(input.feeBps) || input.feeBps < 0 || input.feeBps > 0xffff) throw new Error("Invalid fee tier encoding");
  if (!Number.isSafeInteger(input.direction) || input.direction < 0 || input.direction > 1) throw new Error("Invalid swap direction");
  return Buffer.concat([
    u64Field(0x5a4b43504d4d0003n), limb(input.pool.toBytes()), limb(input.pool.toBytes().subarray(16)),
    limb(input.assetIn.toBytes()), limb(input.assetIn.toBytes().subarray(16)), limb(input.assetOut.toBytes()), limb(input.assetOut.toBytes().subarray(16)),
    field(input.root), u64Field(input.rootSequence), u64Field(input.generation), field(input.nullifier),
    u64Field(input.reserveIn), u64Field(input.reserveOut), u64Field(BigInt(input.feeBps)), u64Field(input.amountIn), u64Field(input.amountOut),
    u64Field(input.changeAmount), field(input.changeCommitment), field(input.outputCommitment), u64Field(BigInt(input.direction)), u64Field(1n), u64Field(input.swapNonce),
  ]);
}

export interface ProductionProverConfig {
  executablePath: string;
  privateSwapPkPath: string;
  unshieldPkPath: string;
  timeoutMs?: number;
}

function targetKey(): string { return `${platform}-${arch}`; }

async function sha256File(path: string): Promise<string> {
  return createHash("sha256").update(await import("node:fs/promises").then(fs => fs.readFile(path))).digest("hex");
}

async function verifyArtifact(path: string, circuit: "private" | "unshield"): Promise<void> {
  const expected = circuit === "private" ? PRODUCTION_ARTIFACT_SHA256.privateSwapPk : PRODUCTION_ARTIFACT_SHA256.unshieldPk;
  const expectedSize = circuit === "private" ? PRODUCTION_ARTIFACT_SIZE.privateSwapPk : PRODUCTION_ARTIFACT_SIZE.unshieldPk;
  const info = await stat(path);
  if (!info.isFile() || info.size !== expectedSize) throw new Error(`Production ${circuit} proving-key size mismatch`);
  if ((await sha256File(path)).toLowerCase() !== expected) throw new Error(`Production ${circuit} proving-key hash mismatch`);
}

function boundedChild(
  executable: string,
  args: string[],
  input: Buffer | undefined,
  limits: { stdout: number; stderr: number; timeoutMs: number },
): Promise<{ stdout: Buffer; stderr: Buffer }> {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { env: { RUST_BACKTRACE: "0" }, shell: false, stdio: ["pipe", "pipe", "pipe"] });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutLength = 0;
    let stderrLength = 0;
    let settled = false;
    const finish = (error?: Error) => { if (settled) return; settled = true; clearTimeout(timer); if (error) reject(error); else resolve({ stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr) }); };
    const kill = (error: Error) => { child.kill("SIGKILL"); finish(error); };
    const timer = setTimeout(() => kill(new Error("Production prover timed out")), limits.timeoutMs);
    child.on("error", error => finish(error));
    child.stdout.on("data", chunk => { stdoutLength += chunk.length; if (stdoutLength > limits.stdout) kill(new Error("Production prover stdout exceeded its limit")); else stdout.push(Buffer.from(chunk)); });
    child.stderr.on("data", chunk => { stderrLength += chunk.length; if (stderrLength > limits.stderr) kill(new Error("Production prover stderr exceeded its limit")); else stderr.push(Buffer.from(chunk)); });
    child.on("close", code => { if (code === 0) finish(); else finish(new Error(`Production prover failed with exit code ${code ?? "unknown"}`)); });
    if (input) { child.stdin.end(input); } else child.stdin.end();
  });
}

async function verifyExecutable(path: string): Promise<string> {
  const resolved = await realpath(path);
  const info = await stat(resolved);
  const parent = await stat(dirname(resolved));
  if (!info.isFile()) throw new Error("Production prover executable is not a regular file");
  if (process.platform !== "win32" && ((info.mode | parent.mode) & 0o022) !== 0) throw new Error("Production prover executable or directory is writable by group/other");
  const expected = PRIVATE_PROVER_SHA256_BY_TARGET[targetKey()];
  if (!expected || expected === "RELEASE_BUILD_REQUIRED") throw new Error(`No authenticated production prover digest for ${targetKey()}`);
  if ((await sha256File(resolved)).toLowerCase() !== expected) throw new Error("Production prover executable hash mismatch");
  const version = await boundedChild(resolved, ["--version"], undefined, { stdout: 256, stderr: 1024, timeoutMs: 2_000 });
  if (version.stdout.toString("utf8") !== `${PROVER_VERSION}\n`) throw new Error("Production prover version mismatch");
  return resolved;
}

function pathTokens(witness: MerkleWitness): string[] {
  if (witness.index < 0n || witness.index >= 1n << 16n || witness.siblings.length !== 16) throw new Error("Invalid Merkle witness");
  return [decimal(witness.index), decimal(witness.generation), ...witness.siblings.map(value => hex(requireBytes32(value, "Merkle sibling")))];
}

function requestFrame(circuit: "private" | "unshield", tokens: string[]): Buffer {
  const frame = `zkcpmm-prover-ipc-v1\n${circuit}\n${tokens.length}\n${tokens.join("\n")}\n`;
  const encoded = Buffer.from(frame, "utf8");
  if (encoded.length > 16 * 1024) throw new Error("Production prover request exceeds its limit");
  return encoded;
}

function parseOutput(circuit: "private" | "unshield", output: Buffer): { proof: Uint8Array; publicInputs: Uint8Array } {
  const inputLength = circuit === "private" ? 704 : 320;
  if (output.length !== 16 + 256 + inputLength || !output.subarray(0, 4).equals(PROVER_OUTPUT_MAGIC) || output[4] !== 1 || output[5] !== (circuit === "private" ? 0 : 1) || output.readUInt16BE(6) !== 0 || output.readUInt32BE(8) !== 256 || output.readUInt32BE(12) !== inputLength) throw new Error("Invalid production prover response frame");
  return { proof: output.subarray(16, 272), publicInputs: output.subarray(272) };
}

async function prove(config: ProductionProverConfig, circuit: "private" | "unshield", tokens: string[]): Promise<{ proof: Uint8Array; publicInputs: Uint8Array }> {
  const executable = await verifyExecutable(config.executablePath);
  await verifyArtifact(circuit === "private" ? config.privateSwapPkPath : config.unshieldPkPath, circuit);
  const request = requestFrame(circuit, tokens);
  try {
    const result = await boundedChild(executable, ["--stdin-v1", circuit, "--pk", circuit === "private" ? config.privateSwapPkPath : config.unshieldPkPath], request, { stdout: circuit === "private" ? 977 : 593, stderr: 16 * 1024, timeoutMs: Math.min(Math.max(config.timeoutMs ?? 120_000, 1_000), 300_000) });
    return parseOutput(circuit, result.stdout);
  } finally {
    request.fill(0);
  }
}

export class ProductionProver implements Prover {
  constructor(private readonly config: ProductionProverConfig) {}

  async proveUnshield(input: UnshieldProverInput) {
    const tokens = [hex(input.pool.toBytes()), hex(input.asset.toBytes()), hex(requireBytes32(input.root, "root")), hex(requireBytes32(input.nullifier, "nullifier")), decimal(input.amount), hex(input.recipient.toBytes()), hex(requireBytes32(input.spendSecret, "spend secret")), hex(requireBytes32(input.randomness, "randomness")), ...pathTokens(input.witness)];
    return prove(this.config, "unshield", tokens);
  }

  async provePrivateSwap(input: PrivateSwapProverInput) {
    const tokens = [hex(input.pool.toBytes()), hex(input.assetIn.toBytes()), hex(input.assetOut.toBytes()), hex(requireBytes32(input.root, "root")), decimal(input.rootSequence), decimal(input.generation), hex(requireBytes32(input.nullifier, "nullifier")), decimal(input.reserveIn), decimal(input.reserveOut), String(input.feeBps), decimal(input.amountIn), decimal(input.amountOut), decimal(input.changeAmount), hex(requireBytes32(input.changeCommitment, "change commitment")), hex(requireBytes32(input.outputCommitment, "output commitment")), String(input.direction), decimal(input.swapNonce), hex(requireBytes32(input.inputSpendSecret, "input spend secret")), hex(requireBytes32(input.inputRandomness, "input randomness")), ...pathTokens(input.witness), hex(requireBytes32(input.changeSpendSecret, "change spend secret")), hex(requireBytes32(input.changeRandomness, "change randomness")), hex(requireBytes32(input.outputSpendSecret, "output spend secret")), hex(requireBytes32(input.outputRandomness, "output randomness"))];
    return prove(this.config, "private", tokens);
  }
}
