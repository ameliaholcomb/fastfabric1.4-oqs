
# FastFabric


**Note:** This is a fork of the Hyperledger Fabric repository (https://github.com/hyperledger/fabric) and contains a more stable implementation of the FastFabric (https://ieeexplore.ieee.org/document/8751452). The original code used for the publication can be found in the `fastfabric` branch.

This is a proof of concept and not meant to be used in a production setting. Helper scripts and instructions are included to run Fabric directly from the binaries created by this repository.


## Prerequisites

- The Hyperledger Fabric prerequisites are installed
- `$GOPATH` and `$GOPATH/bin` are added to `$PATH`


## First Steps
1. Install PQFabric

        mkdir -p $GOPATH/src/github.com/hyperledger/
        cd $GOPATH/src/github.com/hyperledger/
        git clone https://github.com/ameliaholcomb/fastfabric1.4-oqs.git

2. Make directories for Hyperledger artifacts and the new binaries you are about to build

        mkdir -p $GOPATH/src/github.com/hyperledger/fabric/.build/bin
        sudo mkdir -p -m777 /var/hyperledger/production

## OQS-Specific instructions
To run quantum-safe hyperledger, perform the following steps.
(Tested on Ubuntu 16.04, golang 1.13, C++21)


1. Install liboqs 0.4.0. You can read the full instructions [here](https://github.com/open-quantum-safe/liboqs/tree/0.4.0/README.md).
I have copied the details for Ubuntu below with appropriate flags:

        sudo apt install cmake gcc ninja-build libssl-dev python3-pytest unzip xsltproc doxygen graphviz
        git clone -b master https://github.com/open-quantum-safe/liboqs.git
        cd liboqs
        git checkout tags/0.4.0
    
Configure and build:

        mkdir build && cd build
        cmake -GNinja -DBUILD_SHARED_LIBS=ON
        ninja

Currently, the libdir and includedir flags aren't working for me. Instead, after running
the `make` command, I copy `liboqs/.libs/*` and `liboqs/include/*` into `/usr/local/lib`
 and `/usr/local/include`, respectively.
 
        sudo cp -a liboqs/.libs/* /usr/local/lib
        sudo cp -a liboqs/include/* /usr/local/include

1. Help Go find the shared library:

        export PATH=$PATH:/usr/local/lib
        sudo ldconfig
        
1. Run the following commands to build executables that can create a quantum-safe hybrid crypto config.
Do not use the cryptogen and configtxgen executables from another source. 

        cd hyperledger/fabric/common/tools/cryptogen && go build
        cd hyperledger/fabric/common/tools/configtxgen && go build
        cd $GOPATH/src/github.com/hyperledger/fabric
        mkdir -r .build/bin
        mv common/tools/cryptogen/cryptogen .build/bin
        mv common/tools/configtxgen/configtxgen .build/bin

## Stop and Test
At this stage, you should try running a few unit tests to make sure everything is correctly set up.

- Test that the OQS library is installed correctly and Fabric can use it through its go wrapper.

        cd $GOPATH/src/hyperledger/fabric/
        go test -v external_crypto/

## Network Setup Instructions

Now you can set up a local hyperledger blockchain.
All following steps use scripts from the  `fabric/fastfabric/scripts` folder.
- Fill in the values for the variables in `custom_parameters.sh` based on the comments in the file.
  For example, to run on a single server on localhost, the file would look like:
  
      export PEER_DOMAIN="local"
      export FAST_PEER_ADDRESS="localhost"
      export ENDORSER_ADDRESS=""
      export STORAGE_ADDRESS=""
      export ORDERER_DOMAIN="local"
      export ORDERER_ADDRESS="localhost"
      
- Run `create_artifacts.sh` to create the prerequisite files to setup the network, channel and anchor peer.
- For the following steps it is advised to run them in different terminals or use `tmux`.
    - Run `run_orderer.sh` on the respective server that should form the ordering service
    - Run `run_endorser.sh` on any server that should act as a decoupled endorser
    - Run `run_fastpeer.sh` on the server that should validate incoming blocks
    - Run `channel_setup.sh` on any server in the network.
    - Run `chaincode_setup.sh` on any server in the network. If you want to install different chaincode, modify the script accordingly. The command should have the form `./chaincode_setup.sh [lower limit of account index range] [upper limit of account index range] [value per account]`. Example: `./chaincode_setup.sh 0 10 100`

This should set up an orderer in solo mode, one or more endorsers, a persistent storage peer and fast validation peer. **Important:** Sometimes it takes a few seconds after `channel_setup.sh` for the peers to properly set up a gossip network and as a result the `chaincode_setup.sh` might fail. In this case wait a short while and try to run it again.

For a test you can run `test_chaincode [any endorser server]` to move 10 coins form `account0` to `account1`. Example: `./test_chaincode localhost`

To shut down all Fabric nodes run `terminate_benchmark.sh`

## Fabric Client Instructions
All following steps use scripts from the  `fabric/fastfabric/scripts/client` folder, and the commands are assumed to be run from that folder.

- Create the environment variables needed based on the custom parameters set above.

        source ../base_parameters.sh
        source ../custom_parameters.sh

- Run `node addToWallet.js` to copy the necessary user credentials from the `crypto-config` folder into the `wallet` folder.
- Compile either the `invoke.ts` (a client that endorses and submits transactions in one go) or `invoke2.ts` script (a client that first caches all endorsements before submitting them in bulk to the ordering service) to Javascript (change the `include` line in `tsconfig.json`). See https://code.visualstudio.com/docs/typescript/typescript-compiling for help.
- Depending on your choice modify `run_benchmark.sh` to either run `invoke.ts` or `invoke2.ts`. Run it with the command `./run_benchmark.sh [lower thread index] [upper thread index exclusive] [total thread count] [endorser addr] [number of touched accounts] [percentage of contentious txs]`. This allows to create multiple client threads on multiple servers (wherever this script is executed), to generate load.
Example: `./run_benchmark.sh 0 10 50 localhost 20000 70`. This spawns 10 threads on this server (and expects that the script is run on other servers to spawn 40 more threads) and calls an endorser on localhost to endorse the transactions. Because only a fifth of the total threads are spawned by this script, only the first fifth of the accounts are touched, in this case `account0` to `account3999` for a total of 2000 transactions. There is a 70% chance that any generated transaction touches `account0` and `account1` instead of a previously untouched pair to simulate a transaction conflict.  

## Possible Errors and Remedies
- Compilation errors when building cryptogen that reference type mismatches in external_crypto/oqs.go:
Check that liboqs was built at the right version (0.4.0). Check that golang is at the right version (1.13).
If cryptogen has errors when running (in create_artifacts.sh), run 

        go test -v external_crypto/
    to understand if the OQS wrapper is working correctly, and whether the errors affect all algorithms or just some.

- Docker permission errors when running chaincode_setup: Make sure the docker group has the appropriate permissions.

        sudo usermod -aG docker ${USER}
        newgrp docker
        


