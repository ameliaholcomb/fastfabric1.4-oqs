/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package committer

import (
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/core/ledger"
	"github.com/hyperledger/fabric/fastfabric/cached"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/utils"
	"github.com/pkg/errors"
	"sync"
)

var logger = flogging.MustGetLogger("committer")

//--------!!!IMPORTANT!!-!!IMPORTANT!!-!!IMPORTANT!!---------
// This is used merely to complete the loop for the "skeleton"
// path so we can reason about and  modify committer component
// more effectively using code.

// PeerLedgerSupport abstract out the API's of ledger.PeerLedger interface
// required to implement LedgerCommitter
type PeerLedgerSupport interface {
	GetPvtDataAndBlockByNum(blockNum uint64, filter ledger.PvtNsCollFilter) (*ledger.BlockAndPvtData, error)

	GetPvtDataByNum(blockNum uint64, filter ledger.PvtNsCollFilter) ([]*ledger.TxPvtData, error)

	CommitWithPvtData(blockAndPvtdata *ledger.BlockAndPvtData, commitOpts *ledger.CommitOptions) error

	CommitPvtDataOfOldBlocks(blockPvtData []*ledger.BlockPvtData) ([]*ledger.PvtdataHashMismatch, error)

	GetBlockchainInfo() (*common.BlockchainInfo, error)

	DoesPvtDataInfoExist(blockNum uint64) (bool, error)

	GetBlockByNumber(blockNumber uint64) (*common.Block, error)

	GetConfigHistoryRetriever() (ledger.ConfigHistoryRetriever, error)

	GetMissingPvtDataTracker() (ledger.MissingPvtDataTracker, error)

	Close()
}

// LedgerCommitter is the implementation of  Committer interface
// it keeps the reference to the ledger to commit blocks and retrieve
// chain information
type LedgerCommitter struct {
	PeerLedgerSupport
	eventer    ConfigBlockEventer
	commitLock sync.Mutex
	blocks     map[uint64]struct {
		*ledger.BlockAndPvtData
		e chan error
		c *ledger.CommitOptions
	}
	commitHeight uint64
	ready        chan struct {
		*ledger.BlockAndPvtData
		e chan error
		c *ledger.CommitOptions
	}
	done chan bool
}

// ConfigBlockEventer callback function proto type to define action
// upon arrival on new configuaration update block
type ConfigBlockEventer func(block *cached.Block) error

// NewLedgerCommitter is a factory function to create an instance of the committer
// which passes incoming blocks via validation and commits them into the ledger.
func NewLedgerCommitter(ledger PeerLedgerSupport) *LedgerCommitter {
	return NewLedgerCommitterReactive(ledger, func(_ *cached.Block) error { return nil })
}

// NewLedgerCommitterReactive is a factory function to create an instance of the committer
// same as way as NewLedgerCommitter, while also provides an option to specify callback to
// be called upon new configuration block arrival and commit event
func NewLedgerCommitterReactive(l PeerLedgerSupport, eventer ConfigBlockEventer) *LedgerCommitter {
	lc := &LedgerCommitter{
		PeerLedgerSupport: l,
		eventer:           eventer,
		commitLock:        sync.Mutex{},
		blocks: map[uint64]struct {
			*ledger.BlockAndPvtData
			e chan error
			c *ledger.CommitOptions
		}{},
		commitHeight: 1,
		ready: make(chan struct {
			*ledger.BlockAndPvtData
			e chan error
			c *ledger.CommitOptions
		}, 10000),
		done: make(chan bool, 1),
	}
	go lc.commitWithPvtData()
	return lc
}

// preCommit takes care to validate the block and update based on its
// content
func (lc *LedgerCommitter) preCommit(block *cached.Block) error {
	// Updating CSCC with new configuration block
	if utils.IsConfigBlock(block) {
		logger.Debug("Received configuration update, calling CSCC ConfigUpdate")
		if err := lc.eventer(block); err != nil {
			return errors.WithMessage(err, "could not update CSCC with new configuration update")
		}
	}
	return nil
}

func (lc *LedgerCommitter) Close() {
	if len(lc.done) == 0 {
		lc.done <- true
	}
	lc.PeerLedgerSupport.Close()
}

// CommitWithPvtData commits blocks atomically with private data
func (lc *LedgerCommitter) CommitWithPvtData(blockAndPvtData *ledger.BlockAndPvtData, commitOpts *ledger.CommitOptions) <-chan error {
	errChan := make(chan error, 1)
	lc.commitLock.Lock()
	defer lc.commitLock.Unlock()

	lc.blocks[blockAndPvtData.Block.Header.Number] = struct {
		*ledger.BlockAndPvtData
		e chan error
		c *ledger.CommitOptions
	}{
		BlockAndPvtData: blockAndPvtData,
		e:               errChan,
		c:               commitOpts,
	}
	lc.FillQueue()

	return errChan
}

// CommitWithPvtData commits blocks atomically with private data
func (lc *LedgerCommitter) commitWithPvtData() {
	for {
		select {
		case <-lc.done:
			return
		case data := <-lc.ready:
			// Do validation and whatever needed before
			// committing new block
			if err := lc.preCommit(data.Block); err != nil {
				data.e <- err
				continue
			}

			// Committing new block
			if err := lc.PeerLedgerSupport.CommitWithPvtData(data.BlockAndPvtData, data.c); err != nil {
				data.e <- err
				continue
			}
			data.e <- nil
		}
	}
}

// GetPvtDataAndBlockByNum retrieves private data and block for given sequence number
func (lc *LedgerCommitter) GetPvtDataAndBlockByNum(seqNum uint64) (*ledger.BlockAndPvtData, error) {
	return lc.PeerLedgerSupport.GetPvtDataAndBlockByNum(seqNum, nil)
}

// LedgerHeight returns recently committed block sequence number
func (lc *LedgerCommitter) LedgerHeight() (uint64, error) {
	var info *common.BlockchainInfo
	var err error
	if info, err = lc.GetBlockchainInfo(); err != nil {
		logger.Errorf("Cannot get blockchain info, %s", info)
		return uint64(0), err
	}

	return info.Height, nil
}

// DoesPvtDataInfoExistInLedger returns true if the ledger has pvtdata info
// about a given block number.
func (lc *LedgerCommitter) DoesPvtDataInfoExistInLedger(blockNum uint64) (bool, error) {
	return lc.DoesPvtDataInfoExist(blockNum)
}

// GetBlocks used to retrieve blocks with sequence numbers provided in the slice
func (lc *LedgerCommitter) GetBlocks(blockSeqs []uint64) []*common.Block {
	var blocks []*common.Block

	for _, seqNum := range blockSeqs {
		if blck, err := lc.GetBlockByNumber(seqNum); err != nil {
			logger.Errorf("Not able to acquire block num %d, from the ledger skipping...", seqNum)
			continue
		} else {
			logger.Debug("Appending next block with seqNum = ", seqNum, " to the resulting set")
			blocks = append(blocks, blck)
		}
	}

	return blocks
}

func (lc *LedgerCommitter) FillQueue() {
	data, ok := lc.blocks[lc.commitHeight]
	for ok {
		lc.ready <- data
		delete(lc.blocks, lc.commitHeight)
		lc.commitHeight += 1
		data, ok = lc.blocks[lc.commitHeight]
	}
}
