import { PublicKey } from "@solana/web3.js";

export const DEVNET_FIXTURE_LOOKUP_TABLE = new PublicKey("FMVUyVx6byt3dVV7nmkbXbsu5fLQPM8gTdJwN5YYL9HC");
export const DEVNET_FIXTURE_LOOKUP_ADDRESSES = [
  "EV9QP9oDHdMna6jhSygVgZrCNK1tj8jQxoHgnmPWs53K",
  "9gZtbSFppxYA1exTKZnKeoD56CbHAmDcvTxtkuC8d3dp",
  "7vNrKUFtbpxbXf3YFzrp2iP5oMgcLkdYoeeezmGWRgqn",
  "7SoeykDmMeETErv8Dg9U2Bdhz8jTmYtRGD2iYxVVuk1T",
  "4ZCU44rgHUWTnWmuSArtBuaVApwvcnptZqtSf4ekS2qy",
  "3a3osayztwwU4xDEb7JYj3kx7FqUevm5ShDcjGNwpatX",
  "CPQFWxfmd8eaBS1qBxk4RS1wQ9fAz2X8HEKxWNoByzhJ",
  "o648Yd8CV6xBAKNVjbgRJzQUquchZiiiKLu2To2WrQ6",
  "3Hoc6vs9d2AwW6scbpwPK8B7RyrwnmRtLfjAgsmN4Nsx",
  "GF7vadR56d9yxm8Q29NkMCtGHWpmSBTiSw2r6Jxax5Pr",
  "HWufLScxwj5dnttn2xjofuncdCWBaX27DBa1fpaLmGk4",
  "AL9ZezLEh1DKS1Jaq3WeCNViJUWS25P4bisb34x3vRq",
  "9NxRoVLV8Mhtu3mrjd8RDFVDJ4igEPZ5TcwMYYheXHAp",
  "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
  "11111111111111111111111111111111",
].map(value => new PublicKey(value));

export function lookupTableConfig(address, expectedAuthority) {
  const value = address instanceof PublicKey ? address : new PublicKey(address);
  if (!value.equals(DEVNET_FIXTURE_LOOKUP_TABLE)) return value;
  return {
    address: value,
    expectedAuthority,
    expectedAddresses: DEVNET_FIXTURE_LOOKUP_ADDRESSES,
  };
}
