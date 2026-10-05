# Private Send Transaction Size Report

Date: 2026-10-05

The capture used the deployed Devnet pool, production prover, finalized RPC
reads, and `FMVUyVx6byt3dVV7nmkbXbsu5fLQPM8gTdJwN5YYL9HC`. The capture hook
intercepted `sendRawTransaction` after signing and before submission. Raw
signed bytes were parsed for this report and are not checked into the repo.

## Exact Accounting

All byte components below sum to the serialized v0 transaction length.

| Component | Self unshield | Bob Private Send |
|---|---:|---:|
| Signature count prefix + signature | 65 | 65 |
| Version | 1 | 1 |
| Message header | 3 | 3 |
| Static-account count prefix | 1 | 1 |
| Static account keys | 192 | 224 |
| Recent blockhash | 32 | 32 |
| Instruction count prefix | 1 | 1 |
| Serialized instructions | 707 | 707 |
| LUT count prefix | 1 | 1 |
| Serialized LUT lookup | 43 | 43 |
| **Total** | **1046** | **1078** |

The compute-budget instruction has 5 data bytes and serializes to 8 bytes.
The frozen unshield instruction has 681 data bytes and serializes to 699
bytes. Its proof is 256 bytes and its public-input buffer is 320 bytes in both
captures. Instruction data and all short-vector prefix widths are identical.

With the older partial table
`2LDxX9aeVaQhTjcDtwBqCGzA8Nm9MGGCShwnGSKzDYwy`, the corresponding totals are
1201 bytes for self-unshield and 1233 bytes for Bob Private Send:

| Component | Self unshield | Bob Private Send |
|---|---:|---:|
| Signatures | 65 | 65 |
| Version + header | 4 | 4 |
| Static-account count prefix | 1 | 1 |
| Static account keys | 352 | 384 |
| Recent blockhash | 32 | 32 |
| Instruction count prefix + instructions | 708 | 708 |
| LUT count prefix + lookup | 39 | 39 |
| **Total** | **1201** | **1233** |

## Account Classification

The fixture LUT loads the stable protocol accounts:

- LUT writable: shielded state, Merkle tree, custody A, custody B.
- LUT readonly: pool, mint A, mint B, SPL Token program, System Program.
- Static signer: payer.
- Static dynamic accounts: recipient ATAs, spent-nullifier PDA, and, for an arbitrary recipient, the recipient owner.
- Static transaction programs: Compute Budget and zkCPMM program.

Self-unshield deduplicates the recipient owner with the payer signer. Bob
Private Send therefore has exactly one additional 32-byte static key. Dynamic
recipient and ATA accounts were not moved into the LUT.

The Bob capture resolved the accounts as follows:

| Account | Class | Public key |
|---|---|---|
| Payer | static signer | `7hmajuVWXD9iQv8LooaSraSJ6CryJv4WJXKU8gd5H6e` |
| Bob recipient | static dynamic | `DxfHMmAtoQETi6fNauaakciikVriAZtbUhr7FnnC24aC` |
| Bob Asset-A ATA | static dynamic | `3kDLcyDGFSmYgsRHHpppzvXhNs4m1Rf8Rf2jU5bVXPjp` |
| Bob Asset-B ATA | static dynamic | `4UQsFRmxvW66FS9j7dWYZjk2EjCDhvYZ6Uswz4EA29Ry` |
| Spent-nullifier PDA | static dynamic | `FMSbMZ9A8jPrtqSFQWguPgy6X1ip3b7gnTkp2SBJ6sk1` |
| Compute Budget | static | `ComputeBudget111111111111111111111111111111` |
| zkCPMM program | static | `ZkCP47fAJJREdXNKSBvTsgJAuLoTKepgk6opmqsHobm` |
| Shielded state | LUT writable | `9gZtbSFppxYA1exTKZnKeoD56CbHAmDcvTxtkuC8d3dp` |
| Merkle tree | LUT writable | `7vNrKUFtbpxbXf3YFzrp2iP5oMgcLkdYoeeezmGWRgqn` |
| Custody A | LUT writable | `7SoeykDmMeETErv8Dg9U2Bdhz8jTmYtRGD2iYxVVuk1T` |
| Custody B | LUT writable | `4ZCU44rgHUWTnWmuSArtBuaVApwvcnptZqtSf4ekS2qy` |
| Pool | LUT readonly | `EV9QP9oDHdMna6jhSygVgZrCNK1tj8jQxoHgnmPWs53K` |
| Asset-A mint | LUT readonly | `3a3osayztwwU4xDEb7JYj3kx7FqUevm5ShDcjGNwpatX` |
| Asset-B mint | LUT readonly | `CPQFWxfmd8eaBS1qBxk4RS1wQ9fAz2X8HEKxWNoByzhJ` |
| SPL Token program | LUT readonly | `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` |
| System Program | LUT readonly | `11111111111111111111111111111111` |

## Devnet Evidence

The current pinned fixture scripts passed all six flows with `E2E_FULL=1`:

- Shield: `3BTrkPbDoKx4F9uz9rh1MaReQT7KYNsojx6bP4ZWvSaTh3fkVezc51cicZjDT7NLxHYA2n1fj5ovYkXZUL9hnxsw`
- Private Swap: `4nRfmV5SKsP7zZVgzqMEcRhRTJjyLok2aSh1AYJVUaveGqkay28b95SaoPBYJ6sSHsxuavGumdcso8yetfmSJdn8`
- Unshield: `5oJWDbJANnUd2BsXqLrwy39KYSGTQoqWjmxr4zRXRT5KmBf89DKNecB1aaXgT1qdw4BPqhsMp5D7zAVHSr438Wcq`
- Private Send: `5i6wtc2BsSLQ4krznRvk6jufM8kyqPYwWDFSxeXLLWnxXp7ZVvBqP3z3mdYs4rTnA7hqdc2FHa77vUGDf34hpRim`
- Private Swap -> Private Send: `419iJy5vuYvNdCzQsQDTL5emb6893gLsYNCn9qJV3Q2SzQh5g2UWkPwQ3HS9bCujr6RHT4LwjYFD1J9R7eHbjmz6`, `3oPH1MMbzyBnFq3BKsps81LtjqBz55scHWv9MXirB9DQoqZbQNegQ1V5WvTvku3SPtVyVQCqBebpg7iaJ77shFJT`
- Full lifecycle: `4DgzCdFg4Gi5i62oac66gKeGuJNRx4KweoVVj1D3duPcAeWXhgSXhmdG7oDe7wXv1VwxT3yrDY4NXdM4Kiuh8gT`, `4BN3DDLia2m2iwEMKv4DWWQFfw3hzs8WeG39RpqdEGM9BmUXYPY3QqeyrDQ9Qpr8ZwPtg5F3ZM3824Uh4ZXAhnH9`, `5r5iZYpAMvAw2o1PPYjmuLGWAWSYA8b6uAHVUjYieJonNDuWJSHfZnkjzkRZDTvVtjsqfS4r7smiM7CjvJDwXFyG`, `2d3k12gLhCztitcaNEf6Fu5pgkybB2EuZRZGnVBNZ5RbTwkrCCXnFppnc2u4wvHiQCnjarkcB4Apt14A3ZxVwNC5`

A separate process reopened the encrypted store and authenticated the Merkle
checkpoint: 9 notes verified, 1 available, 8 spent, tree sequence 119, and no
pending operations.
