/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kvledger

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"

	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric/common/ledger/blkstorage"
	"github.com/hyperledger/fabric/core/chaincode/implicitcollection"
	"github.com/hyperledger/fabric/core/ledger"
	"github.com/hyperledger/fabric/core/ledger/confighistory"
	"github.com/hyperledger/fabric/core/ledger/internal/version"
	"github.com/hyperledger/fabric/core/ledger/kvledger/msgs"
	"github.com/hyperledger/fabric/core/ledger/kvledger/txmgmt/pvtstatepurgemgmt"
	"github.com/hyperledger/fabric/core/ledger/pvtdatapolicy"
	"github.com/hyperledger/fabric/internal/fileutil"
	"github.com/pkg/errors"
)

const (
	snapshotSignableMetadataFileName   = "_snapshot_signable_metadata.json"
	snapshotAdditionalMetadataFileName = "_snapshot_additional_metadata.json"
	jsonFileIndent                     = "    "
	simpleKeyValueDB                   = "SimpleKeyValueDB"
)

// snapshotSignableMetadata is used to build a JSON that represents a unique snapshot and
// can be signed by the peer. Hashsum of the resultant JSON is intended to be used as a single
// hash of the snapshot, if need be.
type snapshotSignableMetadata struct {
	ChannelName            string            `json:"channel_name"`
	LastBlockNumber        uint64            `json:"last_block_number"`
	LastBlockHashInHex     string            `json:"last_block_hash"`
	PreviousBlockHashInHex string            `json:"previous_block_hash"`
	FilesAndHashes         map[string]string `json:"snapshot_files_raw_hashes"`
	StateDBType            string            `json:"state_db_type"`
}

func (m *snapshotSignableMetadata) toJSON() ([]byte, error) {
	return json.MarshalIndent(m, "", jsonFileIndent)
}

type snapshotAdditionalMetadata struct {
	SnapshotHashInHex        string `json:"snapshot_hash"`
	LastBlockCommitHashInHex string `json:"last_block_commit_hash"`
}

func (m *snapshotAdditionalMetadata) toJSON() ([]byte, error) {
	return json.MarshalIndent(m, "", jsonFileIndent)
}

type snapshotMetadata struct {
	*snapshotSignableMetadata
	*snapshotAdditionalMetadata
}

type snapshotMetadataJSONs struct {
	signableMetadata   string
	additionalMetadata string
}

func (j *snapshotMetadataJSONs) toMetadata() (*snapshotMetadata, error) {
	metadata := &snapshotSignableMetadata{}
	if err := json.Unmarshal([]byte(j.signableMetadata), metadata); err != nil {
		return nil, errors.Wrap(err, "error while unmarshaling signable metadata")
	}

	additionalMetadata := &snapshotAdditionalMetadata{}
	if err := json.Unmarshal([]byte(j.additionalMetadata), additionalMetadata); err != nil {
		return nil, errors.Wrap(err, "error while unmarshaling additional metadata")
	}
	return &snapshotMetadata{
		snapshotSignableMetadata:   metadata,
		snapshotAdditionalMetadata: additionalMetadata,
	}, nil
}

// generateSnapshot generates a snapshot. This function should be invoked when commit on the kvledger are paused
// after committing the last block fully and further the commits should not be resumed till this function finishes
func (l *kvLedger) generateSnapshot() error {
	snapshotsRootDir := l.config.SnapshotsConfig.RootDir
	bcInfo, err := l.GetBlockchainInfo()
	if err != nil {
		return err
	}
	lastBlockNum := bcInfo.Height - 1
	snapshotTempDir, err := ioutil.TempDir(
		InProgressSnapshotsPath(snapshotsRootDir),
		fmt.Sprintf("%s-%d-", l.ledgerID, lastBlockNum),
	)
	if err != nil {
		return errors.Wrapf(err, "error while creating temp dir [%s]", snapshotTempDir)
	}
	newHashFunc := func() (hash.Hash, error) {
		return l.hashProvider.GetHash(snapshotHashOpts)
	}
	txIDsExportSummary, err := l.blockStore.ExportTxIds(snapshotTempDir, newHashFunc)
	if err != nil {
		return err
	}
	configsHistoryExportSummary, err := l.configHistoryRetriever.ExportConfigHistory(snapshotTempDir, newHashFunc)
	if err != nil {
		return err
	}
	stateDBExportSummary, err := l.txmgr.ExportPubStateAndPvtStateHashes(snapshotTempDir, newHashFunc)
	if err != nil {
		return err
	}

	if err := l.generateSnapshotMetadataFiles(
		snapshotTempDir, txIDsExportSummary,
		configsHistoryExportSummary, stateDBExportSummary,
	); err != nil {
		return err
	}
	if err := fileutil.SyncDir(snapshotTempDir); err != nil {
		return err
	}
	slgr := SnapshotsDirForLedger(snapshotsRootDir, l.ledgerID)
	if err := os.MkdirAll(slgr, 0755); err != nil {
		return errors.Wrapf(err, "error while creating final dir for snapshot:%s", slgr)
	}
	if err := fileutil.SyncParentDir(slgr); err != nil {
		return err
	}
	slgrht := SnapshotDirForLedgerBlockNum(snapshotsRootDir, l.ledgerID, lastBlockNum)
	if err := os.Rename(snapshotTempDir, slgrht); err != nil {
		return errors.Wrapf(err, "error while renaming dir [%s] to [%s]:", snapshotTempDir, slgrht)
	}
	return fileutil.SyncParentDir(slgrht)
}

func (l *kvLedger) generateSnapshotMetadataFiles(
	dir string,
	txIDsExportSummary,
	configsHistoryExportSummary,
	stateDBExportSummary map[string][]byte) error {
	// generate metadata file
	filesAndHashes := map[string]string{}
	for fileName, hashsum := range txIDsExportSummary {
		filesAndHashes[fileName] = hex.EncodeToString(hashsum)
	}
	for fileName, hashsum := range configsHistoryExportSummary {
		filesAndHashes[fileName] = hex.EncodeToString(hashsum)
	}
	for fileName, hashsum := range stateDBExportSummary {
		filesAndHashes[fileName] = hex.EncodeToString(hashsum)
	}
	bcInfo, err := l.GetBlockchainInfo()
	if err != nil {
		return err
	}

	stateDBType := l.config.StateDBConfig.StateDatabase
	if stateDBType != ledger.CouchDB {
		stateDBType = simpleKeyValueDB
	}
	signableMetadata := &snapshotSignableMetadata{
		ChannelName:            l.ledgerID,
		LastBlockNumber:        bcInfo.Height - 1,
		LastBlockHashInHex:     hex.EncodeToString(bcInfo.CurrentBlockHash),
		PreviousBlockHashInHex: hex.EncodeToString(bcInfo.PreviousBlockHash),
		FilesAndHashes:         filesAndHashes,
		StateDBType:            stateDBType,
	}

	signableMetadataBytes, err := signableMetadata.toJSON()
	if err != nil {
		return errors.Wrap(err, "error while marshelling snapshot metadata to JSON")
	}
	if err := fileutil.CreateAndSyncFile(filepath.Join(dir, snapshotSignableMetadataFileName), signableMetadataBytes, 0444); err != nil {
		return err
	}

	// generate metadata hash file
	hash, err := l.hashProvider.GetHash(snapshotHashOpts)
	if err != nil {
		return err
	}
	if _, err := hash.Write(signableMetadataBytes); err != nil {
		return err
	}

	additionalMetadata := &snapshotAdditionalMetadata{
		SnapshotHashInHex:        hex.EncodeToString(hash.Sum(nil)),
		LastBlockCommitHashInHex: hex.EncodeToString(l.commitHash),
	}

	additionalMetadataBytes, err := additionalMetadata.toJSON()
	if err != nil {
		return errors.Wrap(err, "error while marshalling snapshot additional metadata to JSON")
	}
	return fileutil.CreateAndSyncFile(filepath.Join(dir, snapshotAdditionalMetadataFileName), additionalMetadataBytes, 0444)
}

// CreateFromSnapshot implements the corresponding method from interface ledger.PeerLedgerProvider
// This function creates a new ledger from the supplied snapshot. If a failure happens during this
// process, the partially created ledger is deleted
func (p *Provider) CreateFromSnapshot(snapshotDir string) (ledger.PeerLedger, string, error) {
	metadataJSONs, err := loadSnapshotMetadataJSONs(snapshotDir)
	if err != nil {
		return nil, "", errors.WithMessagef(err, "error while loading metadata")
	}

	metadata, err := metadataJSONs.toMetadata()
	if err != nil {
		return nil, "", errors.WithMessagef(err, "error while unmarshaling metadata")
	}

	if err := verifySnapshot(snapshotDir, metadata, p.initializer.HashProvider); err != nil {
		return nil, "", errors.WithMessagef(err, "error while verifying snapshot")
	}

	ledgerID := metadata.ChannelName
	lastBlockNum := metadata.LastBlockNumber

	lastBlkHash, err := hex.DecodeString(metadata.LastBlockHashInHex)
	if err != nil {
		return nil, "", errors.Wrapf(err, "error while decoding last block hash")
	}
	previousBlkHash, err := hex.DecodeString(metadata.PreviousBlockHashInHex)
	if err != nil {
		return nil, "", errors.Wrapf(err, "error while decoding previous block hash")
	}

	snapshotInfo := &blkstorage.SnapshotInfo{
		LastBlockNum:      lastBlockNum,
		LastBlockHash:     lastBlkHash,
		PreviousBlockHash: previousBlkHash,
	}

	if err = p.idStore.createLedgerID(
		ledgerID,
		&msgs.LedgerMetadata{
			Status: msgs.Status_UNDER_CONSTRUCTION,
			BootSnapshotMetadata: &msgs.BootSnapshotMetadata{
				SingableMetadata:   metadataJSONs.signableMetadata,
				AdditionalMetadata: metadataJSONs.additionalMetadata,
			},
		},
	); err != nil {
		return nil, "", errors.WithMessagef(err, "error while creating ledger id")
	}

	savepoint := version.NewHeight(lastBlockNum, math.MaxUint64)

	if err = p.blkStoreProvider.ImportFromSnapshot(ledgerID, snapshotDir, snapshotInfo); err != nil {
		return nil, "", p.deleteUnderConstructionLedger(
			nil,
			ledgerID,
			errors.WithMessage(err, "error while importing data into block store"),
		)
	}

	if err = p.configHistoryMgr.ImportFromSnapshot(metadata.ChannelName, snapshotDir); err != nil {
		return nil, "", p.deleteUnderConstructionLedger(
			nil,
			ledgerID,
			errors.WithMessage(err, "error while importing data into config history Mgr"),
		)
	}
	btlPolicy := pvtdatapolicy.ConstructBTLPolicy(
		&mostRecentCollectionConfigFetcher{
			DeployedChaincodeInfoProvider: p.initializer.DeployedChaincodeInfoProvider,
			Retriever:                     p.configHistoryMgr.GetRetriever(ledgerID),
		},
	)
	purgeMgrBuilder := pvtstatepurgemgmt.NewPurgeMgrBuilder(ledgerID, btlPolicy, p.bookkeepingProvider)

	if err = p.dbProvider.ImportFromSnapshot(ledgerID, savepoint, snapshotDir, purgeMgrBuilder); err != nil {
		return nil, "", p.deleteUnderConstructionLedger(
			nil,
			ledgerID,
			errors.WithMessage(err, "error while importing data into state db"),
		)
	}

	if p.historydbProvider != nil {
		if err := p.historydbProvider.MarkStartingSavepoint(ledgerID, savepoint); err != nil {
			return nil, "", p.deleteUnderConstructionLedger(
				nil,
				ledgerID,
				errors.WithMessage(err, "error while preparing history db"),
			)
		}
	}

	lgr, err := p.open(ledgerID, metadata, true)
	if err != nil {
		return nil, "", p.deleteUnderConstructionLedger(
			lgr,
			ledgerID,
			errors.WithMessage(err, "error while opening ledger"),
		)
	}

	if err = p.idStore.updateLedgerStatus(ledgerID, msgs.Status_ACTIVE); err != nil {
		return nil, "", p.deleteUnderConstructionLedger(
			lgr,
			ledgerID,
			errors.WithMessage(err, "error while updating the ledger status to Status_ACTIVE"),
		)
	}
	return lgr, ledgerID, nil
}

func loadSnapshotMetadataJSONs(snapshotDir string) (*snapshotMetadataJSONs, error) {
	signableMetdataFilePath := filepath.Join(snapshotDir, snapshotSignableMetadataFileName)
	signableMetadataBytes, err := ioutil.ReadFile(signableMetdataFilePath)
	if err != nil {
		return nil, err
	}
	additionalMetadataFilePath := filepath.Join(snapshotDir, snapshotAdditionalMetadataFileName)
	additionalMetadataBytes, err := ioutil.ReadFile(additionalMetadataFilePath)
	if err != nil {
		return nil, err
	}
	return &snapshotMetadataJSONs{
		signableMetadata:   string(signableMetadataBytes),
		additionalMetadata: string(additionalMetadataBytes),
	}, nil
}

func verifySnapshot(snapshotDir string, snapshotMetadata *snapshotMetadata, hashProvider ledger.HashProvider) error {
	if err := verifyFileHash(
		snapshotDir,
		snapshotSignableMetadataFileName,
		snapshotMetadata.SnapshotHashInHex,
		hashProvider,
	); err != nil {
		return err
	}

	filesAndHashes := snapshotMetadata.FilesAndHashes
	for f, h := range filesAndHashes {
		if err := verifyFileHash(snapshotDir, f, h, hashProvider); err != nil {
			return err
		}
	}
	return nil
}

func verifyFileHash(dir, file string, expectedHashInHex string, hashProvider ledger.HashProvider) error {
	hashImpl, err := hashProvider.GetHash(snapshotHashOpts)
	if err != nil {
		return err
	}

	filePath := filepath.Join(dir, file)
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(hashImpl, bufio.NewReader(f))
	if err != nil {
		return err
	}
	hashInHex := hex.EncodeToString(hashImpl.Sum(nil))
	if hashInHex != expectedHashInHex {
		return errors.Errorf("hash mismatch for file [%s]. Expected hash = [%s], Actual hash = [%s]",
			file, expectedHashInHex, hashInHex,
		)
	}
	return nil
}

type mostRecentCollectionConfigFetcher struct {
	*confighistory.Retriever
	ledger.DeployedChaincodeInfoProvider
}

func (c *mostRecentCollectionConfigFetcher) CollectionInfo(chaincodeName, collectionName string) (*peer.StaticCollectionConfig, error) {
	isImplicitCollection, mspID := implicitcollection.MspIDIfImplicitCollection(collectionName)
	if isImplicitCollection {
		return c.GenerateImplicitCollectionForOrg(mspID), nil
	}

	explicitCollections, err := c.MostRecentCollectionConfigBelow(math.MaxUint64, chaincodeName)
	if err != nil || explicitCollections == nil || explicitCollections.CollectionConfig == nil {
		return nil, errors.WithMessage(err, "error while fetching most recent collection config")
	}

	for _, c := range explicitCollections.CollectionConfig.Config {
		stateCollectionConfig := c.GetStaticCollectionConfig()
		if stateCollectionConfig.Name == collectionName {
			return stateCollectionConfig, nil
		}
	}
	return nil, nil
}
