# gnark-tests
This repository is forked from https://github.com/Consensys/gnark-tests

This repo contains tests (interop or integration) that may drag some extra dependencies, for the following projects:

* [`gnark`: a framework to execute (and verify) algorithms in zero-knowledge](https://github.com/consensys/gnark) 
* [`gnark-crypto`](https://github.com/consensys/gnark-crypto)

Note that since the verifying key of the contract is included in the `solidity/contract.sol`, changes to gnark version or circuit should result in regenerating keys and solidity contracts.

It needs `solc` and `abigen` (1.10.17-stable).


## TO generate ZK proofs

```bash
cd solidity/contract
go run main.go
```

## TO verify the ZK proofs

```bash
cd solidity/contract
python3 verify.py
```