# Blockchain-driven optimistic fair exchange based on PVSS and zkSNARKs

we propose a blockchain driven optimistic fair exchange protocol based on PVSS and zkSNARKs. 
The exchange between a buyer and a seller is divided into 5 phases. 
Seller's data is encrypted using AES with a PVSS secret as the key for privacy. 
zkSNARKs generate proofs for data validity. 
The seller provides a NIZK proof for key validation after the buyer pays with digital assets. 
Data is submitted to the blockchain and verified via smart contracts. 
The PVSS scheme allows arbiters to assist the honest buyer in key recovery, ensuring fairness and privacy of shared data while eliminating single-node failures.

## The phases included in the exchange protocol
Initialization phase, 
Commit data phase, 
Transfer asset phase,
Reveal key phase 
and Recovery phase (optional).


**zkSNARKs** 

We choose the Groth16 scheme.
Particularly, we use the “gnark” library developed using Go language to build
the Groth16 proof and to generate a smart contract codes for verifying the proof.

superseded by https://github.com/ConsenSys/gnark-solidity-checker and CI tests in gnark directly. 
This repo contains tests (interop or integration) that may drag some extra dependencies, for the following projects:
* [`gnark`: a framework to execute (and verify) algorithms in zero-knowledge](https://github.com/consensys/gnark) 
* [`gnark-crypto`](https://github.com/consensys/gnark-crypto)

Note that since the verifying key of the contract is included in the `solidity/contract.sol`, changes to gnark version or circuit should result in running `go generate`  to regenerate keys and solidity contracts.

It needs `solc` and `abigen` (1.10.17-stable).

We integrated zkSNAKRs into `Exchange.py`, so if you want to run zkSNAKRs separately, run `run.py` and `main.go`.

**PVSS** 

The onchain smart contracts are implemented using solidity and compiled by solidity compiler “solc”. 
Additionally, we leverage the “web3.py” library on python for smart contract interaction. 
Our PVSS protocol uses the curve "BN128" both onchain and offchain throughout, since the operations for this curve are avail-
able as precompiles on Ethereum.


# Run exchange protocol

```bash
pyhon3 Exchange.py
```