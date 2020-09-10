/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"
	"os"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/integration/chaincode/benchmark"
)

func main() {
	err := shim.Start(new(BenchmarkChaincode))
	if err != nil {
		fmt.Printf("Error starting benchmark chaincode: %s", err)
	}

}
