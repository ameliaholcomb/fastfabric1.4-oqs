
# FastFabric


**Note:** This is a fork of the Hyperledger Fabric repository (https://github.com/hyperledger/fabric) and contains a more stable implementation of the FastFabric (https://ieeexplore.ieee.org/document/8751452). The original code used for the publication can be found in the `fastfabric` branch.

This is a proof of concept and not meant to be used in a production setting. Helper scripts and instructions are included to run Fabric directly from the binaries created by this repository.


## Prerequisites

- The Hyperledger Fabric prerequisites are installed
- `$GOPATH` and `$GOPATH/bin` are added to `$PATH`
- The instructions assume that the repository is cloned to `$GOPATH/src/github.com/hyperledger/fabric`
- Add the `cryptogen`and `configtxgen` binaries to a new `$GOPATH/src/github.com/hyperledger/fabric/fastfabric/scripts/bin` folder


## Network Setup Instructions

All following steps use scripts from the  `fabric/fastfabric/scripts` folder.
- Fill in the values for the variables in `custom_parameters.sh` based on the comments in the file.
- Run `create_artifact.sh` to create the prerequisite files to setup the network, channel and anchor peer.
- For the following steps it is advised to run them in different terminals or use `tmux`.
    - Run `run_orderer.sh` on the respective server that should form the ordering service
    - Run `run_storage.sh` on the server that should persist the blockchain and world state
    - Run `run_endorser.sh` on any server that should act as a decoupled endorser
    - Run `run_fastpeer.sh` on the server that should validate incoming blocks
    - Run `channel_setup.sh` on any server in the network.
    - Run `chaincode_setup.sh` on any server in the network. If you want to install different chaincode, modify the script accordingly. The command should have the form `./chaincode_setup.sh [lower limit of account index range] [upper limit of account index range] [value per account]`. Example: `./chaincode_setup.sh 0 10 100`

This should set up an orderer in solo mode, one or more endorsers, a persistent storage peer and fast validation peer. **Important:** Sometimes it takes a few seconds after `channel_setup.sh` for the peers to properly set up a gossip network and as a result the `chaincode_setup.sh` might fail. In this case wait a short while and try to run it again.

For a test you can run `test_chaincode [any endorser server]` to move 10 coins form `account0` to `account1`. Example: `./test_chaincode localhost`

To shut down all Fabric nodes run `terminate_benchmark.sh`

## Fabric Client Instructions
All following steps use scripts from the  `fabric/fastfabric/scripts/client` folder.

- First run `node addToWallet.js` to copy the necessary user credentials from the `crypto-config` folder into the `wallet` folder.
- Compile either the `invoke.ts` (a client that endorses and submits transactions in one go) or `invoke2.ts` script (a client that first caches all endorsements before submitting them in bulk to the ordering service) to Javascript (change the `include` line in `tsconfig.json`). See https://code.visualstudio.com/docs/typescript/typescript-compiling for help.
- Depending on your choice modify `run_benchmark.sh` to either run `invoke.ts` or `invoke2.ts`. Run it with the command `.\run_benchmark.sh [lower thread index] [upper thread index exclusive] [total thread count] [endorser addr] [number of touched accounts] [percentage of contentious txs]`. This allows to create multiple client threads on multiple servers (wherever this script is executed), to generate load.
Example: `./run_benchmark.sh 0 10 50 localhost 20000 70`. This spawns 10 threads on this server (and expects that the script is run on other servers to spawn 40 more threads) and calls an endorser on localhost to endorse the transactions. Because only a fifth of the total threads are spawned by this script, only the first fifth of the accounts are touched, in this case `account0` to `account3999` for a total of 2000 transactions. There is a 70% chance that any generated transaction touches `account0` and `account1` instead of a previously untouched pair to simulate a transaction conflict.  
