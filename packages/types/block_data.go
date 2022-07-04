package types

import (
	"bytes"
	"fmt"

	"github.com/gogo/protobuf/proto"

	"github.com/IBAX-io/go-ibax/packages/common/crypto"
	"github.com/IBAX-io/go-ibax/packages/consts"
	"github.com/IBAX-io/go-ibax/packages/converter"
	"github.com/pkg/errors"
)

const (
	minBlockSize = 9
)

var (
	ErrMaxBlockSize = func(max int64, size int) error {
		return fmt.Errorf("block size exceeds maximum %d limit, size is %d", max, size)
	}
	ErrMinBlockSize = func(min int, size int) error {
		return fmt.Errorf("block size exceeds minimum %d limit, size is %d", min, size)
	}
	ErrZeroBlockSize   = errors.New("Block size is zero")
	ErrUnmarshallBlock = errors.New("Unmarshall block")
)

//BlockData is a structure of the block's header
type BlockData struct {
	BlockID        int64
	Time           int64
	EcosystemID    int64
	KeyID          int64
	NodePosition   int64
	Sign           []byte
	Hash           []byte
	RollbacksHash  []byte
	Version        int
	ConsensusMode  int8
	CandidateNodes []byte
}

func (b BlockData) String() string {
	return fmt.Sprintf("BlockID:%d, Time:%d, NodePosition %d", b.BlockID, b.Time, b.NodePosition)
}

func blockVer(cur, prev *BlockData) (ret string) {
func blockVer(cur, prev *BlockHeader) (ret string) {
	if cur.Version >= consts.BvRollbackHash {
		ret = fmt.Sprintf(",%x", prev.RollbacksHash)
	}
	return
}

func (b *BlockData) ForSha(prev *BlockData, mrklRoot []byte) string {
func (b *BlockData) ForSha(prev *BlockData, mrklRoot []byte) string {
func (b *BlockHeader) GenHash(prev *BlockHeader, mrklRoot []byte) []byte {
	return crypto.DoubleHash([]byte(b.ForSha(prev, mrklRoot)))
}

func (b *BlockHeader) ForSha(prev *BlockHeader, mrklRoot []byte) string {
	return fmt.Sprintf("%d,%x,%s,%d,%d,%d,%d",
		b.BlockId, prev.BlockHash, mrklRoot, b.Timestamp, b.EcosystemId, b.KeyId, b.NodePosition) +
		blockVer(b, prev)
}

// ForSign from 128 bytes to 512 bytes. Signature of TYPE, BLOCK_ID, PREV_BLOCK_HASH, TIME, WALLET_ID, state_id, MRKL_ROOT
func (b *BlockHeader) ForSign(prev *BlockHeader, mrklRoot []byte) string {
	return fmt.Sprintf("0,%v,%x,%v,%v,%v,%v,%s",
		b.BlockId, prev.BlockHash, b.Timestamp, b.EcosystemId, b.KeyId, b.NodePosition, mrklRoot) +
		blockVer(b, prev)
}

// ParseBlockHeader is parses block header
func ParseBlockHeader(buf *bytes.Buffer, maxBlockSize int64) (header *BlockHeader, err error) {
	if int64(buf.Len()) > maxBlockSize {
		err = ErrMaxBlockSize(maxBlockSize, buf.Len())
		return
	}
	blo := &Block{}
	blo := &Block{}
	blo := &BlockData{}
	if err := blo.UnmarshallBlock(buf.Bytes()); err != nil {
		return BlockData{}, err
		return BlockData{}, err
		return nil, err
	}
	return blo.Header, nil
}

type Block struct {
	Header     BlockData
	PrevHeader *BlockData
	MerkleRoot []byte
	BinData    []byte
	TxFullData [][]byte
type Block struct {
	Header     BlockData
	PrevHeader *BlockData
	MerkleRoot []byte
	BinData    []byte
	TxFullData [][]byte
type BlockDataOption func(b *BlockData) error

func (b *BlockData) Apply(opts ...BlockDataOption) error {
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(b); err != nil {
			return err
		}
	}
	return nil
}

func (b Block) ForSign() string {
func (b Block) ForSign() string {
func WithCurHeader(cur *BlockHeader) BlockDataOption {
	return func(b *BlockData) error {
		b.Header = cur
		return nil
	}
}

func WithPrevHeader(pre *BlockHeader) BlockDataOption {
	return func(b *BlockData) error {
		b.PrevHeader = pre
		return nil
	}
}

func WithTxFullData(data [][]byte) BlockDataOption {
	return func(b *BlockData) error {
		b.TxFullData = data
		return nil
	}
}

func WithAfterTxs(a *AfterTxs) BlockDataOption {
	return func(b *BlockData) error {
		b.AfterTxs = a
		return nil
	}
}
func WithSysUpdate(a bool) BlockDataOption {
	return func(b *BlockData) error {
		b.SysUpdate = a
		return nil
	}
}

func (b BlockData) ForSign() string {
	return b.Header.ForSign(b.PrevHeader, b.MerkleRoot)
}

func (b *Block) GetMerkleRoot() []byte {
func (b *Block) GetMerkleRoot() []byte {
func (b *BlockData) GenMerkleRoot() []byte {
	var mrklArray [][]byte
	for _, tr := range b.TxFullData {
		mrklArray = append(mrklArray, converter.BinToHex(crypto.DoubleHash(tr)))
	}
	if len(mrklArray) == 0 {
		mrklArray = append(mrklArray, []byte("0"))
	}
	return MerkleTreeRoot(mrklArray)
}

func (b *Block) GetSign(key []byte) ([]byte, error) {
func (b *Block) GetSign(key []byte) ([]byte, error) {
func (b *BlockData) GetSign(key []byte) ([]byte, error) {
	forSign := b.ForSign()
	signed, err := crypto.Sign(key, []byte(forSign))
	if err != nil {
		return nil, errors.Wrap(err, "signing block")
	}
	return signed, nil
}

// MarshallBlock is marshalling block
func (b *Block) MarshallBlock(key []byte) ([]byte, error) {
	if b.Header.BlockID != 1 {
		b.MerkleRoot = b.GetMerkleRoot()
		signed, err := b.GetSign(key)
		if err != nil {
			return nil, err
func (b *Block) MarshallBlock(key []byte) ([]byte, error) {
	if b.Header.BlockID != 1 {
		b.MerkleRoot = b.GetMerkleRoot()
		signed, err := b.GetSign(key)
		if err != nil {
			return nil, err
func (b *BlockData) MarshallBlock(key []byte) ([]byte, error) {
	if b.AfterTxs != nil {
		for i := 0; i < len(b.AfterTxs.TxBinLogSql); i++ {
			b.AfterTxs.TxBinLogSql[i] = DoZlibCompress(b.AfterTxs.TxBinLogSql[i])
		}
		b.Header.Sign = signed
		b.Header.Sign = signed
	}
	return msgpack.Marshal(b)
	return msgpack.Marshal(b)
	for i := 0; i < len(b.TxFullData); i++ {
		b.TxFullData[i] = DoZlibCompress(b.TxFullData[i])
	}
	b.MerkleRoot = b.GenMerkleRoot()
	signed, err := b.GetSign(key)
	if err != nil {
		return nil, err
	}
	b.Header.Sign = signed
	b.Header.BlockHash = b.Header.GenHash(b.PrevHeader, b.MerkleRoot)
	return proto.Marshal(b)
}

func (b *Block) UnmarshallBlock(data []byte) error {
func (b *Block) UnmarshallBlock(data []byte) error {
func (b *BlockData) UnmarshallBlock(data []byte) error {
	if len(data) == 0 {
		return ErrZeroBlockSize
	}
	if len(data) < minBlockSize {
		return ErrMinBlockSize(len(data), minBlockSize)
	}
	if err := msgpack.Unmarshal(data, &b); err != nil {
		return errors.Wrap(err, "unmarshalling block")
	}
	if b.AfterTxs != nil {
		for i := 0; i < len(b.AfterTxs.TxBinLogSql); i++ {
			b.AfterTxs.TxBinLogSql[i] = DoZlibUnCompress(b.AfterTxs.TxBinLogSql[i])
		}
	}
	for i := 0; i < len(b.TxFullData); i++ {
		b.TxFullData[i] = DoZlibUnCompress(b.TxFullData[i])
	}
	b.BinData = data
	return nil
}

// MerkleTreeRoot return Merkle value
func MerkleTreeRoot(dataArray [][]byte) []byte {
	result := make(map[int32][][]byte)
	for _, v := range dataArray {
		hash := converter.BinToHex(crypto.DoubleHash(v))
		result[0] = append(result[0], hash)
	}
	var j int32
	for len(result[j]) > 1 {
		for i := 0; i < len(result[j]); i = i + 2 {
			if len(result[j]) <= (i + 1) {
				if _, ok := result[j+1]; !ok {
					result[j+1] = [][]byte{result[j][i]}
				} else {
					result[j+1] = append(result[j+1], result[j][i])
				}
			} else {
				if _, ok := result[j+1]; !ok {
					hash := crypto.DoubleHash(append(result[j][i], result[j][i+1]...))
					hash = converter.BinToHex(hash)
					result[j+1] = [][]byte{hash}
				} else {
					hash := crypto.DoubleHash([]byte(append(result[j][i], result[j][i+1]...)))
					hash = converter.BinToHex(hash)
					result[j+1] = append(result[j+1], hash)
				}
			}
		}
		j++
	}

	ret := result[int32(len(result)-1)]
	return ret[0]
}
