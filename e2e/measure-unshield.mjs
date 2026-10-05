import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Connection, Keypair, PublicKey, VersionedTransaction } from "@solana/web3.js";
import {
  EncryptedFileNoteStore,
  Lethenymous,
  ProductionProver,
  PROGRAM_ID,
  RpcMerkleWitnessProvider,
  keyHierarchy,
  ownerCommitment,
} from "../dist/index.js";
import { lookupTableConfig } from "./fixture.mjs";

const env = process.env;
const rpcUrl = env.E2E_RPC_URL ?? "https://api.devnet.solana.com";
const programId = new PublicKey(env.E2E_PROGRAM_ID ?? PROGRAM_ID);
const pool = new PublicKey(env.E2E_POOL ?? "EV9QP9oDHdMna6jhSygVgZrCNK1tj8jQxoHgnmPWs53K");
const lookupTableAddress = new PublicKey(env.E2E_LOOKUP_TABLE ?? "FMVUyVx6byt3dVV7nmkbXbsu5fLQPM8gTdJwN5YYL9HC");
const expand = value => value?.startsWith("~/") ? resolve(homedir(), value.slice(2)) : resolve(value);
const payerPath = expand(env.E2E_PAYER_KEYPAIR ?? "~/.config/solana/id.json");
if (!env.E2E_BOB_KEYPAIR || !env.E2E_SOURCE_NOTE_STORE || !env.E2E_SEED_PATH) throw new Error("E2E_BOB_KEYPAIR, E2E_SOURCE_NOTE_STORE, and E2E_SEED_PATH are required");
const bobPath = expand(env.E2E_BOB_KEYPAIR);
const sourceStorePath = expand(env.E2E_SOURCE_NOTE_STORE);
const seedPath = expand(env.E2E_SEED_PATH);
const proverPath = expand(env.E2E_PROVER_BIN ?? "../audit/tooling/production-prover/target/release/production-prover");
const privateSwapPkPath = expand(env.E2E_PRIVATE_SWAP_PK ?? "../artifacts/production-groth16-v1/private_swap_pk.production.bin");
const unshieldPkPath = expand(env.E2E_UNSHIELD_PK ?? "../artifacts/production-groth16-v1/unshield_pk.production.bin");
const targetAmount = BigInt(env.E2E_AMOUNT ?? "700");

const keypair = value => Keypair.fromSecretKey(Uint8Array.from(JSON.parse(value)));

function readShortvec(buffer, offset) {
  let value = 0;
  let shift = 0;
  let cursor = offset;
  for (;;) {
    assert(cursor < buffer.length, "shortvec exceeds transaction");
    const byte = buffer[cursor++];
    value |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) return { value, bytes: cursor - offset };
    shift += 7;
    assert(shift < 32, "shortvec is too large");
  }
}

function parseTransaction(serialized, lookupTable) {
  const buffer = Buffer.from(serialized);
  let offset = 0;
  const signatureCount = readShortvec(buffer, offset);
  offset += signatureCount.bytes;
  const signaturesStart = offset;
  offset += signatureCount.value * 64;
  const messageStart = offset;
  const versionByte = buffer[offset++];
  assert((versionByte & 0x80) !== 0, "captured transaction is not versioned");
  const version = versionByte & 0x7f;
  const header = {
    numRequiredSignatures: buffer[offset++],
    numReadonlySignedAccounts: buffer[offset++],
    numReadonlyUnsignedAccounts: buffer[offset++],
  };
  const staticCount = readShortvec(buffer, offset);
  offset += staticCount.bytes;
  const staticKeysStart = offset;
  const staticKeys = [];
  for (let index = 0; index < staticCount.value; index++) {
    staticKeys.push(new PublicKey(buffer.subarray(offset, offset + 32)));
    offset += 32;
  }
  const blockhashStart = offset;
  offset += 32;
  const instructionCount = readShortvec(buffer, offset);
  offset += instructionCount.bytes;
  const instructions = [];
  for (let index = 0; index < instructionCount.value; index++) {
    const start = offset;
    const programIdIndex = buffer[offset++];
    const accountCount = readShortvec(buffer, offset);
    offset += accountCount.bytes;
    const accountIndexes = [...buffer.subarray(offset, offset + accountCount.value)];
    offset += accountCount.value;
    const dataLength = readShortvec(buffer, offset);
    offset += dataLength.bytes;
    const dataStart = offset;
    offset += dataLength.value;
    instructions.push({
      index,
      programIdIndex,
      accountIndexes,
      accountCountPrefixBytes: accountCount.bytes,
      dataLength: dataLength.value,
      dataPrefixBytes: dataLength.bytes,
      serializedBytes: offset - start,
      dataHexPrefix: buffer.subarray(dataStart, Math.min(offset, dataStart + 8)).toString("hex"),
    });
  }
  const lookupCount = readShortvec(buffer, offset);
  offset += lookupCount.bytes;
  const lookups = [];
  for (let index = 0; index < lookupCount.value; index++) {
    const start = offset;
    const accountKey = new PublicKey(buffer.subarray(offset, offset + 32));
    offset += 32;
    const writableCount = readShortvec(buffer, offset);
    offset += writableCount.bytes;
    const writableIndexes = [...buffer.subarray(offset, offset + writableCount.value)];
    offset += writableCount.value;
    const readonlyCount = readShortvec(buffer, offset);
    offset += readonlyCount.bytes;
    const readonlyIndexes = [...buffer.subarray(offset, offset + readonlyCount.value)];
    offset += readonlyCount.value;
    lookups.push({
      index,
      accountKey,
      writableIndexes,
      readonlyIndexes,
      writablePrefixBytes: writableCount.bytes,
      readonlyPrefixBytes: readonlyCount.bytes,
      serializedBytes: offset - start,
    });
  }
  assert.equal(offset, buffer.length, "transaction parser did not consume the full transaction");
  const message = VersionedTransaction.deserialize(buffer).message;
  assert.equal(message.version, 0, "captured transaction is not v0");
  const loadedWritable = [];
  const loadedReadonly = [];
  for (const lookup of lookups) {
    assert(lookup.accountKey.equals(lookupTable.key), "transaction uses an unexpected lookup table");
    for (const index of lookup.writableIndexes) loadedWritable.push(lookupTable.state.addresses[index]);
    for (const index of lookup.readonlyIndexes) loadedReadonly.push(lookupTable.state.addresses[index]);
  }
  const allKeys = [...staticKeys, ...loadedWritable, ...loadedReadonly];
  const classify = index => {
    if (index < staticKeys.length) return index < header.numRequiredSignatures ? "SIGNER_STATIC" : "STATIC";
    const writableEnd = staticKeys.length + loadedWritable.length;
    return index < writableEnd ? "LUT_WRITABLE" : "LUT_READONLY";
  };
  const accounts = allKeys.map((pubkey, index) => ({ index, pubkey: pubkey.toBase58(), class: classify(index) }));
  const instructionDetails = instructions.map(instruction => ({
    ...instruction,
    programId: allKeys[instruction.programIdIndex]?.toBase58(),
    accounts: instruction.accountIndexes.map(index => ({ index, pubkey: allKeys[index]?.toBase58(), class: classify(index) })),
  }));
  const signatureSection = {
    count: signatureCount.value,
    countPrefixBytes: signatureCount.bytes,
    signatureBytes: signatureCount.value * 64,
    totalBytes: signatureCount.bytes + signatureCount.value * 64,
  };
  const messageBreakdown = {
    versionBytes: 1,
    headerBytes: 3,
    staticAccountCountPrefixBytes: staticCount.bytes,
    staticAccountCount: staticCount.value,
    staticAccountBytes: staticCount.value * 32,
    recentBlockhashBytes: 32,
    instructionCountPrefixBytes: instructionCount.bytes,
    instructionBytes: instructions.reduce((total, instruction) => total + instruction.serializedBytes, 0),
    lookupCountPrefixBytes: lookupCount.bytes,
    lookupBytes: lookups.reduce((total, lookup) => total + lookup.serializedBytes, 0),
  };
  messageBreakdown.totalBytes = 1 + messageBreakdown.headerBytes + messageBreakdown.staticAccountCountPrefixBytes + messageBreakdown.staticAccountBytes + messageBreakdown.recentBlockhashBytes + messageBreakdown.instructionCountPrefixBytes + messageBreakdown.instructionBytes + messageBreakdown.lookupCountPrefixBytes + messageBreakdown.lookupBytes;
  const expectedLength = signatureCount.bytes + signatureCount.value * 64 + messageBreakdown.totalBytes;
  assert.equal(expectedLength, buffer.length, "byte accounting does not sum to serialized length");
  return {
    serializedLength: buffer.length,
    version,
    signaturesStart,
    messageStart,
    signatureSection,
    messageHeader: header,
    staticKeysStart,
    staticAccounts: accounts,
    recentBlockhash: buffer.subarray(blockhashStart, blockhashStart + 32).toString("base64"),
    instructions: instructionDetails,
    addressTableLookups: lookups.map(lookup => ({ ...lookup, accountKey: lookup.accountKey.toBase58() })),
    loadedLookupAccounts: [...loadedWritable.map(pubkey => ({ pubkey: pubkey.toBase58(), class: "LUT_WRITABLE" })), ...loadedReadonly.map(pubkey => ({ pubkey: pubkey.toBase58(), class: "LUT_READONLY" }))],
    byteBreakdown: {
      signatures: signatureCount.bytes + signatureCount.value * 64,
      version: 1,
      header: 3,
      staticAccountCountPrefix: staticCount.bytes,
      staticAccounts: staticCount.value * 32,
      recentBlockhash: 32,
      instructionCountPrefix: instructionCount.bytes,
      instructions: messageBreakdown.instructionBytes,
      lookupCountPrefix: lookupCount.bytes,
      addressTableLookups: messageBreakdown.lookupBytes,
      total: expectedLength,
    },
    instructionCountPrefixBytes: instructionCount.bytes,
    lookupCountPrefixBytes: lookupCount.bytes,
    rawBase64: buffer.toString("base64"),
  };
}

function compare(left, right) {
  const leftKeys = new Set(left.staticAccounts.map(account => account.pubkey));
  const rightKeys = new Set(right.staticAccounts.map(account => account.pubkey));
  return {
    byteDelta: right.serializedLength - left.serializedLength,
    staticAccountCountDelta: right.staticAccounts.length - left.staticAccounts.length,
    onlySelfStatic: [...leftKeys].filter(key => !rightKeys.has(key)),
    onlyPrivateSendStatic: [...rightKeys].filter(key => !leftKeys.has(key)),
    selfStaticKeys: left.staticAccounts,
    privateSendStaticKeys: right.staticAccounts,
    instructionDataLengths: left.instructions.map((instruction, index) => ({ index, self: instruction.dataLength, privateSend: right.instructions[index]?.dataLength, delta: (right.instructions[index]?.dataLength ?? 0) - instruction.dataLength })),
    instructionSerializedDeltas: left.instructions.map((instruction, index) => ({ index, self: instruction.serializedBytes, privateSend: right.instructions[index]?.serializedBytes, delta: (right.instructions[index]?.serializedBytes ?? 0) - instruction.serializedBytes })),
    shortvecPrefixChanges: {
      signatureCount: [left.signatureSection.countPrefixBytes, right.signatureSection.countPrefixBytes],
      staticAccountCount: [left.byteBreakdown.staticAccountCountPrefix, right.byteBreakdown.staticAccountCountPrefix],
      instructionCount: [left.instructionCountPrefixBytes, right.instructionCountPrefixBytes],
      lookupCount: [left.lookupCountPrefixBytes, right.lookupCountPrefixBytes],
    },
    lookupSection: {
      self: left.addressTableLookups,
      privateSend: right.addressTableLookups,
    },
  };
}

async function main() {
  const payer = keypair(await readFile(payerPath, "utf8"));
  const bob = keypair(await readFile(bobPath, "utf8"));
  const seed = Uint8Array.from(Buffer.from((await readFile(seedPath, "utf8")).trim(), "hex"));
  const owner = ownerCommitment(keyHierarchy(seed).spendSecret);
  const sourceStore = EncryptedFileNoteStore.fromSeed(sourceStorePath, seed, owner);
  const sourceNotes = await sourceStore.getNotes();
  const sourceNote = sourceNotes.find(note => note.amount === targetAmount && note.state === "submitted") ?? sourceNotes.find(note => note.amount === targetAmount && note.state === "available");
  assert(sourceNote, `no ${targetAmount} note found in source store`);
  const lookupConnection = new Connection(rpcUrl, "confirmed");
  const lookupResponse = await lookupConnection.getAddressLookupTable(lookupTableAddress, { commitment: "finalized" });
  assert(lookupResponse.value, "configured LUT is unavailable");
  const lookupTable = lookupResponse.value;
  const proverOptions = {
    executablePath: proverPath,
    privateSwapPkPath,
    unshieldPkPath,
  };
  const captures = {};
  for (const [label, recipient] of [["selfUnshield", payer.publicKey], ["privateSend", bob.publicKey]]) {
    const directory = await mkdtemp(join(tmpdir(), "zkcpmm-size-capture-"));
    try {
      const store = EncryptedFileNoteStore.fromSeed(join(directory, "notes.lnsj"), seed, owner);
      await store.saveNote({ ...sourceNote, state: "available", spent: false, operationId: undefined, transactionSignature: undefined });
      const connection = new Connection(rpcUrl, "confirmed");
      let captured;
      connection.sendRawTransaction = async serialized => {
        captured = Buffer.from(serialized);
        throw new Error("capture-only: transaction was not submitted");
      };
      let sdk;
      const witnessProvider = new RpcMerkleWitnessProvider(connection, programId, address => sdk.getTree(address), store);
      sdk = new Lethenymous({
        connection,
        wallet: {
          publicKey: payer.publicKey,
          signTransaction: async transaction => { transaction.partialSign(payer); return transaction; },
          signVersionedTransaction: async transaction => { transaction.sign([payer]); return transaction; },
        },
        programId,
        witnessProvider,
        lookupTables: [lookupTableConfig(lookupTableAddress, payer.publicKey)],
      });
      const shielded = sdk.shieldedWallet(seed, new ProductionProver(proverOptions), { noteStore: store });
      try {
        await shielded.privateSend({ pool, mint: sourceNote.asset, amount: sourceNote.amount, recipient });
      } catch (error) {
        if (!captured) throw error;
      }
      assert(captured, `${label} did not reach capture hook`);
      const parsed = parseTransaction(captured, lookupTable);
      captures[label] = { recipient: recipient.toBase58(), ...parsed };
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }
  captures.comparison = compare(captures.selfUnshield, captures.privateSend);
  console.log(JSON.stringify(captures, null, 2));
}

await main();
