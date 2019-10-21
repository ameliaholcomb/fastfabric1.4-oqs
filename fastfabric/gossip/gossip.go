package gossip

import "github.com/hyperledger/fabric/protos/gossip"

var Queue = make(map[uint64]chan *gossip.Payload)
