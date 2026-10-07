import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PublicKey } from "@solana/web3.js";
import {
  accountDiscriminator,
  EncryptedFileNoteStore,
  InMemoryNoteStore,
  MerkleReconstructionError,
  RpcMerkleWitnessProvider,
  ROOT_HISTORY,
  ShieldedWallet,
  TREE_CAPACITY,
  TREE_DEPTH,
  encodeNote,
  encryptNote,
  hash2,
  keyHierarchy,
  noteCommitment,
  nullifier,
  ownerCommitment,
  pda,
  rootFromTree,
} from "../dist/index.js";

const programId = new PublicKey(Uint8Array.from({ length: 32 }, (_, index) => index + 1));
const pool = new PublicKey(Uint8Array.from({ length: 32 }, (_, index) => index + 40));
const [treeAddress] = pda.tree(pool, programId);
const [streamAddress] = pda.shielded(pool, programId);
const zero = () => new Uint8Array(32);
const bytesFor = value => { const result = zero(); result[31] = value; return result; };
const eventId = name => createHash("sha256").update(`event:${name}`).digest().subarray(0, 8);
const SHIELD = eventId("ShieldedNoteAppended");
const SWAP = eventId("PrivateSwapped");
const UNSHIELD = eventId("Unshielded");

function emptyTree() {
  const emptySubtrees = [zero()];
  for (let level = 0; level < TREE_DEPTH; level++) emptySubtrees.push(Uint8Array.from(hash2(emptySubtrees[level], emptySubtrees[level])));
  const tree = {
    pool,
    generation: 0n,
    nextIndex: 0n,
    sequence: 0n,
    frontier: Array.from({ length: TREE_DEPTH }, zero),
    frontierPresent: Array(TREE_DEPTH).fill(0),
    emptySubtrees,
    roots: Array.from({ length: ROOT_HISTORY }, zero),
    rootSequences: Array(ROOT_HISTORY).fill(0n),
    rootGenerations: Array(ROOT_HISTORY).fill(0n),
  };
  tree.roots[0] = Uint8Array.from(emptySubtrees[TREE_DEPTH]);
  return tree;
}

function append(tree, leaf) {
  const index = tree.nextIndex;
  let carry = Uint8Array.from(leaf);
  for (let level = 0; level < TREE_DEPTH; level++) {
    if (((index >> BigInt(level)) & 1n) === 0n) {
      tree.frontier[level] = carry;
      tree.frontierPresent[level] = 1;
      break;
    }
    carry = Uint8Array.from(hash2(tree.frontier[level], carry));
    tree.frontierPresent[level] = 0;
  }
  if (index === TREE_CAPACITY - 1n) {
    tree.frontier[TREE_DEPTH - 1] = carry;
    tree.frontierPresent[TREE_DEPTH - 1] = 1;
  }
  tree.nextIndex++;
  tree.sequence++;
  const root = rootFromTree(tree);
  const slot = Number(tree.sequence % BigInt(ROOT_HISTORY));
  tree.roots[slot] = Uint8Array.from(root);
  tree.rootSequences[slot] = tree.sequence;
  tree.rootGenerations[slot] = tree.generation;
  return { index, sequence: tree.sequence, root: Uint8Array.from(root) };
}

function u64(value) {
  const result = Buffer.alloc(8);
  result.writeBigUInt64LE(BigInt(value));
  return result;
}

function shieldData(commitment, result) {
  const encrypted = Buffer.alloc(186);
  encrypted[0] = 1;
  return Buffer.concat([
    SHIELD,
    pool.toBuffer(),
    Buffer.from([0]),
    u64(42),
    Buffer.from(commitment),
    Buffer.from([186, 0, 0, 0]),
    encrypted,
    Buffer.from(result.root),
    u64(0),
    u64(result.index),
  ]);
}

function swapData(change, output, root, rootSequence, changeIndex, outputIndex) {
  return Buffer.concat([
    SWAP,
    pool.toBuffer(),
    Buffer.from([0]),
    u64(1),
    u64(1),
    Buffer.from(root),
    u64(rootSequence),
    u64(0),
    bytesFor(9),
    Buffer.from(change),
    Buffer.from(output),
    Buffer.from([1]),
    u64(changeIndex),
    u64(outputIndex),
  ]);
}

function unshieldData(nullifier, rootSequence) {
  return Buffer.concat([
    UNSHIELD,
    pool.toBuffer(),
    Buffer.from([0]),
    u64(1),
    new PublicKey(Uint8Array.from({ length: 32 }, (_, index) => index + 80)).toBuffer(),
    Buffer.from(nullifier),
    u64(0),
    u64(rootSequence),
  ]);
}

function transaction(signature, slot, data, transactionProgram = programId) {
  const logs = data ? [
    `Program ${transactionProgram.toBase58()} invoke [1]`,
    `Program data: ${Buffer.from(data).toString("base64")}`,
    `Program ${transactionProgram.toBase58()} success`,
  ] : [];
  return {
    slot,
    meta: { err: null, loadedAddresses: undefined, logMessages: logs },
    transaction: {
      message: {
        getAccountKeys: () => ({ get: index => index === 0 ? transactionProgram : streamAddress }),
        compiledInstructions: [{ programIdIndex: 0, accountKeyIndexes: [1] }],
      },
      signatures: [signature],
    },
    signature,
  };
}

function fakeConnection(history, transactions, calls, overrides = {}) {
  return {
    getGenesisHash: async () => "genesis-test",
    getSignaturesForAddress: async (_address, options) => {
      calls.signatures++;
      const newestFirst = [...history].reverse();
      const start = options?.before ? newestFirst.findIndex(row => row.signature === options.before) + 1 : 0;
      return newestFirst.slice(Math.max(start, 0), Math.max(start, 0) + 1000);
    },
    getTransaction: async signature => {
      calls.transactions.push(signature);
      if (overrides.getTransaction) return overrides.getTransaction(signature);
      return transactions.get(signature) ?? null;
    },
  };
}

function addRow(history, transactions, data, slot, signature = `signature-${history.length + 1}`) {
  history.push({ signature, slot, err: null, confirmationStatus: "finalized" });
  transactions.set(signature, transaction(signature, slot, data));
  return signature;
}

function storeFor(path) {
  const seed = new Uint8Array(32).fill(7);
  const owner = ownerCommitment(keyHierarchy(seed).spendSecret);
  return EncryptedFileNoteStore.fromSeed(path, seed, owner);
}

test("cold sync persists and warm/restarted sync fetches only the finalized suffix", async () => {
  const directory = await mkdtemp(join(tmpdir(), "zkcpmm-witness-"));
  try {
    const history = [];
    const transactions = new Map();
    const calls = { signatures: 0, transactions: [] };
    const currentTree = emptyTree();
    const first = bytesFor(1);
    const firstResult = append(currentTree, first);
    addRow(history, transactions, shieldData(first, firstResult), 10, "signature-1");
    const store = storeFor(join(directory, "notes.lnsj"));
    const connection = fakeConnection(history, transactions, calls);
    const provider = new RpcMerkleWitnessProvider(connection, programId, async () => currentTree, store);

    const coldWitness = await provider.getWitness(pool, first);
    assert.equal(calls.signatures, 1);
    assert.deepEqual(calls.transactions, ["signature-1"]);
    assert.equal(coldWitness.index, 0n);

    const second = bytesFor(2);
    const secondResult = append(currentTree, second);
    addRow(history, transactions, shieldData(second, secondResult), 11, "signature-2");
    const warmWitness = await provider.getWitness(pool, second);
    assert.deepEqual(calls.transactions, ["signature-1", "signature-2"]);
    assert.equal(warmWitness.index, 1n);

    const nullifier = bytesFor(3);
    addRow(history, transactions, unshieldData(nullifier, currentTree.sequence), 12, "signature-3");
    const spent = await provider.getSpentNullifiers(pool);
    assert(spent.some(value => Buffer.from(value).equals(Buffer.from(nullifier))));
    assert.deepEqual(calls.transactions, ["signature-1", "signature-2", "signature-3"]);

    const restartedCalls = { signatures: 0, transactions: [] };
    const restarted = new RpcMerkleWitnessProvider(fakeConnection(history, transactions, restartedCalls), programId, async () => currentTree, store);
    const restartedWitness = await restarted.getWitness(pool, second);
    assert.deepEqual(restartedWitness, warmWitness);
    assert.equal(restartedCalls.signatures, 1);
    assert.deepEqual(restartedCalls.transactions, []);

    const change = bytesFor(4);
    const output = bytesFor(5);
    const inputRoot = rootFromTree(currentTree);
    const swapResult = append(currentTree, change);
    append(currentTree, output);
    addRow(history, transactions, swapData(change, output, inputRoot, swapResult.sequence - 1n, swapResult.index, swapResult.index + 1n), 13, "signature-4");
    const outputWitness = await restarted.getWitness(pool, output);
    assert.equal(outputWitness.index, 3n);
    assert.deepEqual(restartedCalls.transactions, ["signature-4"]);
    assert.equal((await restarted.getShieldEvents(pool)).length, 2);
    assert((await restarted.getSpentNullifiers(pool)).some(value => Buffer.from(value).equals(Buffer.from(bytesFor(9)))));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("cold sync paginates the complete finalized signature history", async () => {
  const directory = await mkdtemp(join(tmpdir(), "zkcpmm-witness-pagination-"));
  try {
    const history = [];
    const transactions = new Map();
    const calls = { signatures: 0, transactions: [] };
    const currentTree = emptyTree();
    for (let index = 0; index < 1001; index++) {
      const leaf = bytesFor((index % 250) + 1);
      const result = append(currentTree, leaf);
      addRow(history, transactions, shieldData(leaf, result), index + 1, `signature-page-${index}`);
    }
    const provider = new RpcMerkleWitnessProvider(
      fakeConnection(history, transactions, calls),
      programId,
      async () => currentTree,
      storeFor(join(directory, "notes.lnsj")),
    );
    const witness = await provider.getWitness(pool, bytesFor(1));
    assert.equal(witness.index, 0n);
    assert.equal(calls.signatures, 2);
    assert.equal(calls.transactions.length, 1001);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("authenticated CPI append history is reconstructed through the stable pool account",async()=>{
  const current=emptyTree(),leaf=bytesFor(71),result=append(current,leaf);
  const history=[],transactions=new Map();addRow(history,transactions,shieldData(leaf,result),10,"cpi-shield");
  const wrapper=new PublicKey(new Uint8Array(32).fill(72));
  const tx=transactions.get("cpi-shield");
  tx.transaction.message.getAccountKeys=()=>({get:i=>[wrapper,programId,pda.shielded(pool,programId)[0]][i]});
  tx.transaction.message.compiledInstructions=[{programIdIndex:0,accountKeyIndexes:[2]}];
  tx.meta.innerInstructions=[{index:0,instructions:[{programIdIndex:1,accounts:[2],data:""}]}];
  tx.meta.logMessages=[`Program ${wrapper} invoke [1]`,...tx.meta.logMessages,`Program ${wrapper} success`];
  const provider=new RpcMerkleWitnessProvider(fakeConnection(history,transactions,{signatures:0,transactions:[]}),programId,async()=>current);
  assert.equal((await provider.getWitness(pool,leaf)).index,0n);
});

test("authenticated v1 tree checkpoints rebuild the pool stream without reusing the old cursor",async()=>{
  const current=emptyTree(),leaf=bytesFor(73),result=append(current,leaf),history=[],transactions=new Map(),calls={signatures:0,transactions:[]};
  const signature=addRow(history,transactions,shieldData(leaf,result),20,"legacy-shield");
  const h=v=>Buffer.from(v).toString("hex");
  const identity={genesisHash:"genesis-test",programId:programId.toBase58(),pool:pool.toBase58(),tree:treeAddress.toBase58(),generation:"0"};
  const base={formatVersion:1,identity,tree:{pool:pool.toBase58(),generation:"0",nextIndex:"1",sequence:"1",frontier:current.frontier.map(h),frontierPresent:current.frontierPresent,emptySubtrees:current.emptySubtrees.map(h),roots:current.roots.map(h),rootSequences:current.rootSequences.map(String),rootGenerations:current.rootGenerations.map(String)},cursor:{lastProcessedSignature:signature,lastFinalizedSlot:20},appends:[{index:"0",sequence:"1",commitment:h(leaf),event:{kind:"shield",pool:pool.toBase58(),asset:0,amount:"42",commitment:h(leaf),encryptedNote:Buffer.concat([Buffer.from([1]),Buffer.alloc(185)]).toString("hex"),root:h(result.root),generation:"0",index:"0",sequence:"1",slot:20,signature}}],spentNullifiers:[],reconstructedRoot:h(result.root)};
  const legacy=Buffer.from(JSON.stringify({...base,integrity:{algorithm:"sha256",digest:createHash("sha256").update(JSON.stringify(base)).digest("hex")}}));
  const checkpoints=new Map([[JSON.stringify(identity),legacy]]);
  const store={loadMerkleCheckpoint:async key=>checkpoints.get(key),saveMerkleCheckpoint:async(key,value)=>{checkpoints.set(key,value);}};
  const provider=new RpcMerkleWitnessProvider(fakeConnection(history,transactions,calls),programId,async()=>current,store);
  assert.equal((await provider.getWitness(pool,leaf)).generation,0n);assert.deepEqual(calls.transactions,[signature]);
  assert([...checkpoints.values()].some(value=>JSON.parse(Buffer.from(value).toString()).kind==="pool-manifest" && JSON.parse(Buffer.from(value).toString()).formatVersion===3));
});

test("corrupted checkpoints fail closed with a typed reconstruction error", async () => {
  const directory = await mkdtemp(join(tmpdir(), "zkcpmm-witness-corrupt-"));
  try {
    const history = [];
    const transactions = new Map();
    const currentTree = emptyTree();
    const leaf = bytesFor(11);
    addRow(history, transactions, shieldData(leaf, append(currentTree, leaf)), 20, "signature-corrupt");
    const path = join(directory, "notes.lnsj");
    const store = storeFor(path);
    const calls = { signatures: 0, transactions: [] };
    const provider = new RpcMerkleWitnessProvider(fakeConnection(history, transactions, calls), programId, async () => currentTree, store);
    await provider.getWitness(pool, leaf);
    const sidecar = (await readdir(directory)).find(name => name.startsWith("notes.lnsj.merkle-"));
    assert(sidecar);
    const data = await readFile(join(directory, sidecar));
    data[data.length - 1] ^= 1;
    await writeFile(join(directory, sidecar), data);
    const restarted = new RpcMerkleWitnessProvider(fakeConnection(history, transactions, { signatures: 0, transactions: [] }), programId, async () => currentTree, store);
    await assert.rejects(() => restarted.getWitness(pool, leaf), error => error instanceof MerkleReconstructionError && error.code === "INVALID_CHECKPOINT");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("missing finalized history and finalized root mismatches fail closed", async () => {
  const directory = await mkdtemp(join(tmpdir(), "zkcpmm-witness-gap-"));
  try {
    const currentTree = emptyTree();
    const leaf = bytesFor(21);
    append(currentTree, leaf);
    const connection = fakeConnection([], new Map(), { signatures: 0, transactions: [] });
    const provider = new RpcMerkleWitnessProvider(connection, programId, async () => currentTree, storeFor(join(directory, "notes.lnsj")));
    await assert.rejects(() => provider.getWitness(pool, leaf), error => error instanceof MerkleReconstructionError && error.code === "ROOT_MISMATCH");

    const badTree = { ...currentTree, roots: currentTree.roots.map(value => Uint8Array.from(value)) };
    badTree.roots[Number(badTree.sequence % BigInt(ROOT_HISTORY))][0] ^= 1;
    const invalidProvider = new RpcMerkleWitnessProvider(connection, programId, async () => badTree, storeFor(join(directory, "other.lnsj")));
    await assert.rejects(() => invalidProvider.getWitness(pool, leaf), error => error instanceof MerkleReconstructionError && error.code === "INVALID_TREE");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("429 history reads use bounded retries and finalized failures do not advance the tree", async () => {
  const directory = await mkdtemp(join(tmpdir(), "zkcpmm-witness-retry-"));
  try {
    const history = [];
    const transactions = new Map();
    const currentTree = emptyTree();
    const leaf = bytesFor(31);
    const result = append(currentTree, leaf);
    addRow(history, transactions, shieldData(leaf, result), 30, "signature-retry");
    const calls = { signatures: 0, transactions: [] };
    let attempts = 0;
    const provider = new RpcMerkleWitnessProvider(
      fakeConnection(history, transactions, calls, {
        getTransaction: async signature => {
          attempts++;
          if (attempts < 3) throw new Error("429 Too Many Requests");
          return transactions.get(signature);
        },
      }),
      programId,
      async () => currentTree,
      storeFor(join(directory, "notes.lnsj")),
    );
    await provider.getWitness(pool, leaf);
    assert.equal(attempts, 3);

    const failedTree = emptyTree();
    const failedHistory = [{ signature: "signature-failed", slot: 31, err: { InstructionError: [0, "custom"] }, confirmationStatus: "finalized" }];
    const failedTransaction = transaction("signature-failed", 31, shieldData(leaf, result));
    failedTransaction.meta.err = { InstructionError: [0, "custom"] };
    const failedProvider = new RpcMerkleWitnessProvider(
      fakeConnection(failedHistory, new Map([["signature-failed", failedTransaction]]), { signatures: 0, transactions: [] }),
      programId,
      async () => failedTree,
      storeFor(join(directory, "failed.lnsj")),
    );
    assert.deepEqual(await failedProvider.getSpentNullifiers(pool), []);
    await assert.rejects(() => failedProvider.getWitness(pool, leaf), /not present/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("wrong-program, duplicate, and generation-mismatched history cannot satisfy reconstruction", async () => {
  const directory = await mkdtemp(join(tmpdir(), "zkcpmm-witness-provenance-"));
  try {
    const leaf = bytesFor(41);
    const alternateProgram = new PublicKey(Uint8Array.from({ length: 32 }, (_, index) => index + 100));

    const wrongTree = emptyTree();
    const wrongResult = append(wrongTree, leaf);
    const wrongHistory = [{ signature: "signature-wrong-program", slot: 40, err: null, confirmationStatus: "finalized" }];
    const wrongTransactions = new Map([["signature-wrong-program", transaction("signature-wrong-program", 40, shieldData(leaf, wrongResult), alternateProgram)]]);
    const wrongProvider = new RpcMerkleWitnessProvider(fakeConnection(wrongHistory, wrongTransactions, { signatures: 0, transactions: [] }), programId, async () => wrongTree, storeFor(join(directory, "wrong.lnsj")));
    await assert.rejects(() => wrongProvider.getWitness(pool, leaf), error => error instanceof MerkleReconstructionError && error.code === "ROOT_MISMATCH");

    const mismatchedTree = emptyTree();
    const mismatchedResult = append(mismatchedTree, leaf);
    const mismatchedHistory = [{ signature: "signature-requested", slot: 40, err: null, confirmationStatus: "finalized" }];
    const mismatchedTransactions = new Map([["signature-requested", transaction("signature-different", 40, shieldData(leaf, mismatchedResult))]]);
    const mismatchedProvider = new RpcMerkleWitnessProvider(fakeConnection(mismatchedHistory, mismatchedTransactions, { signatures: 0, transactions: [] }), programId, async () => mismatchedTree, storeFor(join(directory, "mismatched.lnsj")));
    await assert.rejects(() => mismatchedProvider.getWitness(pool, leaf), error => error instanceof MerkleReconstructionError && error.code === "HISTORY_GAP");

    const duplicateTree = emptyTree();
    const duplicateResult = append(duplicateTree, leaf);
    const duplicateHistory = [
      { signature: "signature-duplicate", slot: 41, err: null, confirmationStatus: "finalized" },
      { signature: "signature-duplicate", slot: 41, err: null, confirmationStatus: "finalized" },
    ];
    const duplicateTransactions = new Map([["signature-duplicate", transaction("signature-duplicate", 41, shieldData(leaf, duplicateResult))]]);
    const duplicateProvider = new RpcMerkleWitnessProvider(fakeConnection(duplicateHistory, duplicateTransactions, { signatures: 0, transactions: [] }), programId, async () => duplicateTree, storeFor(join(directory, "duplicate.lnsj")));
    await assert.rejects(() => duplicateProvider.getWitness(pool, leaf), error => error instanceof MerkleReconstructionError && error.code === "DUPLICATE_EVENT");

    const generationTree = emptyTree();
    generationTree.generation = 1n;
    generationTree.rootGenerations.fill(1n);
    const generationResult = append(generationTree, leaf);
    const generationHistory = [{ signature: "signature-generation", slot: 42, err: null, confirmationStatus: "finalized" }];
    const generationTransactions = new Map([["signature-generation", transaction("signature-generation", 42, shieldData(leaf, generationResult))]]);
    const generationProvider = new RpcMerkleWitnessProvider(fakeConnection(generationHistory, generationTransactions, { signatures: 0, transactions: [] }), programId, async () => generationTree, storeFor(join(directory, "generation.lnsj")));
    await assert.rejects(() => generationProvider.getWitness(pool, leaf), error => error instanceof MerkleReconstructionError && error.code === "GENERATION_MISMATCH");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("shield recovery verifies finalized spent-nullifier account data", async () => {
  const seed = new Uint8Array(32).fill(7);
  const keys = keyHierarchy(seed);
  const owner = ownerCommitment(keys.spendSecret);
  const asset = new PublicKey(Uint8Array.from({ length: 32 }, (_, index) => index + 120));
  const randomness = bytesFor(51);
  const commitment = noteCommitment(pool, asset, 42n, owner, randomness);
  const encryptedNote = encryptNote(encodeNote(pool, asset, 42n, owner, randomness), keys.viewKey, pool, asset, commitment);
  const noteNullifier = nullifier(pool, asset, keys.spendSecret, randomness);
  const spentAccount = Buffer.concat([accountDiscriminator("SpentNullifier"), pool.toBuffer(), Buffer.from(noteNullifier), Buffer.from([1])]);
  const foreignSeed = new Uint8Array(32).fill(8);
  const foreignKeys = keyHierarchy(foreignSeed);
  const foreignOwner = ownerCommitment(foreignKeys.spendSecret);
  const foreignRandomness = bytesFor(52);
  const foreignCommitment = noteCommitment(pool, asset, 43n, foreignOwner, foreignRandomness);
  const foreignEncryptedNote = encryptNote(encodeNote(pool, asset, 43n, foreignOwner, foreignRandomness), foreignKeys.viewKey, pool, asset, foreignCommitment);
  const sdk = {
    programId,
    connection: {
      getMultipleAccountsInfo: async addresses => addresses.map(() => ({ owner: programId, executable: false, data: spentAccount })),
    },
    getShieldedState: async () => ({ tokenAMint: asset, tokenBMint: new PublicKey(Uint8Array.from({ length: 32 }, (_, index) => index + 160)) }),
  };
  const provider = {
    getShieldEvents: async () => [
      { asset: 0, amount: 43n, commitment: foreignCommitment, encryptedNote: foreignEncryptedNote, index: 0n, pool },
      { asset: 0, amount: 42n, commitment, encryptedNote, index: 1n, pool },
    ],
    getSpentNullifiers: async () => [],
  };
  const wallet = new ShieldedWallet(sdk, seed, undefined, provider, new InMemoryNoteStore());
  const recovered = await wallet.recoverShieldedNotes(pool);
  assert.equal(recovered.length, 1);
  assert.equal(recovered[0].state, "spent");
});
