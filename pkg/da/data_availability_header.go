package da

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	rsmt2d "github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d"
	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/cda"
	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/rlnc"
	"github.com/celestiaorg/celestia-app/v8/pkg/appconsts"
	v5 "github.com/celestiaorg/celestia-app/v8/pkg/appconsts/v5"
	"github.com/celestiaorg/celestia-app/v8/pkg/wrapper"
	daproto "github.com/celestiaorg/celestia-app/v8/proto/celestia/core/v1/da"
	squarev2 "github.com/celestiaorg/go-square/v2"
	sharev2 "github.com/celestiaorg/go-square/v2/share"
	squarev3 "github.com/celestiaorg/go-square/v3"
	sharev3 "github.com/celestiaorg/go-square/v3/share"
	squarev4 "github.com/celestiaorg/go-square/v4"
	sharev4 "github.com/celestiaorg/go-square/v4/share"
	"github.com/cometbft/cometbft/crypto/merkle"
	"github.com/cometbft/cometbft/types"
	bls12381kzg "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
)

var (
	maxExtendedSquareWidth = appconsts.SquareSizeUpperBound * 2
	minExtendedSquareWidth = appconsts.MinSquareSize * 2
	kateChunks             = 4
)

// DataAvailabilityHeader (DAHeader) contains the Kate commitments of the
// erasure coded version of the data in Block.Data. The original Block.Data is
// split into shares and arranged in a square of width squareSize. Then, this
// square is "extended" into an extended data square (EDS) of width 2*squareSize
// by applying Reed-Solomon encoding. For details see Section 5.2 of
// https://arxiv.org/abs/1809.09044 or the Celestia specification:
// https://github.com/celestiaorg/celestia-specs/blob/master/src/specs/data_structures.md#availabledataheader
type DataAvailabilityHeader struct {
	// KateCommits stores all per-column commitments for the extended data square.
	KateCommits [][]byte `json:"kate_commits"`
	// hash is the Merkle root of all column commitments. This field is the
	// memoized result from `Hash()`.
	hash []byte
}

// NewDataAvailabilityHeader generates a DataAvailability header using the
// provided extended data square.
func NewDataAvailabilityHeader(eds *rsmt2d.ExtendedDataSquare) (DataAvailabilityHeader, error) {
	if eds == nil {
		return DataAvailabilityHeader{}, errors.New("nil extended data square")
	}

	if err := computeAndSetKateCommitments(eds); err != nil {
		return DataAvailabilityHeader{}, err
	}

	kateCommits, err := eds.KateCols()
	if err != nil {
		return DataAvailabilityHeader{}, err
	}

	dah := DataAvailabilityHeader{
		KateCommits: kateCommits,
		hash:        merkle.HashFromByteSlices(kateCommits),
	}

	return dah, nil
}

func computeAndSetKateCommitments(eds *rsmt2d.ExtendedDataSquare) error {
	width := int(eds.Width())
	if width == 0 {
		return errors.New("eds width cannot be zero")
	}

	codec := rlnc.NewRLNCCodec(kateChunks)
	srsSize := uint64(width * codec.MaxChunks())
	srs, err := bls12381kzg.NewSRS(srsSize, big.NewInt(-1))
	if err != nil {
		return err
	}

	kzg := cda.NewGnarkKZG(*srs)
	_, err = cda.ComputeAndSetKateCommitments(codec, eds, kzg)
	return err
}

// ConstructEDS constructs an ExtendedDataSquare from the given transactions and app version.
// If maxSquareSize is less than 0, it will use the upper bound square size for the given app version.
func ConstructEDS(txs [][]byte, appVersion uint64, maxSquareSize int) (*rsmt2d.ExtendedDataSquare, error) {
	switch appVersion {
	case 0:
		return nil, fmt.Errorf("app version cannot be 0")
	case 1, 2, 3, 4, 5: // versions 1-5 are all compatible with v2 of the square package
		if maxSquareSize < 0 {
			maxSquareSize = v5.SquareSizeUpperBound
		}
		// all versions 5 and below have the same parameters and algorithm
		square, err := squarev2.Construct(txs, maxSquareSize, v5.SubtreeRootThreshold)
		if err != nil {
			return nil, err
		}
		return ExtendShares(sharev2.ToBytes(square))
	case 6, 7: // versions 6-7 are compatible with v3 of the square package
		if maxSquareSize < 0 {
			maxSquareSize = appconsts.SquareSizeUpperBound
		}
		square, err := squarev3.Construct(txs, maxSquareSize, appconsts.SubtreeRootThreshold)
		if err != nil {
			return nil, err
		}
		return ExtendShares(sharev3.ToBytes(square))
	default: // assume all other versions are compatible with v4 of the square package
		if maxSquareSize < 0 {
			maxSquareSize = appconsts.SquareSizeUpperBound
		}
		square, err := squarev4.Construct(txs, maxSquareSize, appconsts.SubtreeRootThreshold)
		if err != nil {
			return nil, err
		}
		return ExtendShares(sharev4.ToBytes(square))
	}
}

// ConstructEDSWithTreePool constructs an ExtendedDataSquare from the given transactions and app version,
// it uses treePool to optimize allocations.
// If maxSquareSize is less than 0, it will use the upper bound square size for the given app version.
func ConstructEDSWithTreePool(txs [][]byte, appVersion uint64, maxSquareSize int, treePool *wrapper.TreePool) (*rsmt2d.ExtendedDataSquare, error) {
	switch appVersion {
	case 0:
		return nil, fmt.Errorf("app version cannot be 0")
	case 1, 2, 3, 4, 5: // versions 1-5 are all compatible with v2 of the square package
		if maxSquareSize < 0 {
			maxSquareSize = v5.SquareSizeUpperBound
		}
		// all versions 5 and below have the same parameters and algorithm
		square, err := squarev2.Construct(txs, maxSquareSize, v5.SubtreeRootThreshold)
		if err != nil {
			return nil, err
		}
		return ExtendSharesWithTreePool(sharev2.ToBytes(square), treePool)
	case 6, 7: // versions 6-7 are compatible with v3 of the square package
		if maxSquareSize < 0 {
			maxSquareSize = appconsts.SquareSizeUpperBound
		}
		square, err := squarev3.Construct(txs, maxSquareSize, appconsts.SubtreeRootThreshold)
		if err != nil {
			return nil, err
		}
		return ExtendSharesWithTreePool(sharev3.ToBytes(square), treePool)
	default: // assume all other versions are compatible with v4 of the square package
		if maxSquareSize < 0 {
			maxSquareSize = appconsts.SquareSizeUpperBound
		}
		square, err := squarev4.Construct(txs, maxSquareSize, appconsts.SubtreeRootThreshold)
		if err != nil {
			return nil, err
		}
		return ExtendSharesWithTreePool(sharev4.ToBytes(square), treePool)
	}
}

func ExtendShares(s [][]byte) (*rsmt2d.ExtendedDataSquare, error) {
	// Check that the length of the square is a power of 2.
	if !squarev4.IsPowerOfTwo(len(s)) {
		return nil, fmt.Errorf("number of shares is not a power of 2: got %d", len(s))
	}
	squareSize, err := squarev4.Size(len(s))
	if err != nil {
		return nil, err
	}

	// here we construct a tree
	// Note: uses the nmt wrapper to construct the tree.
	return rsmt2d.ComputeExtendedDataSquare(s, appconsts.DefaultCodec(), wrapper.NewConstructor(uint64(squareSize)))
}

// ExtendSharesWithTreePool injects tree pool into rsmt2d to reuse allocs in root computation
func ExtendSharesWithTreePool(s [][]byte, treePool *wrapper.TreePool) (*rsmt2d.ExtendedDataSquare, error) {
	// Check that the length of the square is a power of 2.
	if !squarev4.IsPowerOfTwo(len(s)) {
		return nil, fmt.Errorf("number of shares is not a power of 2: got %d", len(s))
	}
	// here we construct a tree
	// Note: uses the nmt wrapper to construct the tree.
	return rsmt2d.ComputeExtendedDataSquareWithBuffer(s, appconsts.DefaultCodec(), treePool)
}

// String returns hex representation of merkle hash of the DAHeader.
func (dah *DataAvailabilityHeader) String() string {
	if dah == nil {
		return "<nil DAHeader>"
	}
	return fmt.Sprintf("%X", dah.Hash())
}

// Equals checks equality of two DAHeaders.
func (dah *DataAvailabilityHeader) Equals(to *DataAvailabilityHeader) bool {
	return bytes.Equal(dah.Hash(), to.Hash())
}

// Hash computes the Merkle root of all column commitments. Hash memoizes the
// result in `DataAvailabilityHeader.hash`.
func (dah *DataAvailabilityHeader) Hash() []byte {
	if dah == nil {
		return merkle.HashFromByteSlices(nil)
	}
	if len(dah.hash) != 0 {
		return dah.hash
	}

	// The single data root is computed using a simple binary merkle tree over
	// all column commitments.
	dah.hash = merkle.HashFromByteSlices(dah.KateCommits)
	return dah.hash
}

func (dah *DataAvailabilityHeader) ToProto() (*daproto.DataAvailabilityHeader, error) {
	if dah == nil {
		return nil, errors.New("nil DataAvailabilityHeader")
	}

	dahp := new(daproto.DataAvailabilityHeader)
	// Keep wire compatibility by encoding Kate commitments in `column_roots`.
	dahp.ColumnRoots = dah.KateCommits
	return dahp, nil
}

func DataAvailabilityHeaderFromProto(dahp *daproto.DataAvailabilityHeader) (dah *DataAvailabilityHeader, err error) {
	if dahp == nil {
		return nil, errors.New("nil DataAvailabilityHeader")
	}

	dah = new(DataAvailabilityHeader)
	dah.KateCommits = dahp.ColumnRoots

	return dah, dah.ValidateBasic()
}

// ValidateBasic runs stateless checks on the DataAvailabilityHeader.
func (dah *DataAvailabilityHeader) ValidateBasic() error {
	if dah == nil {
		return errors.New("nil data availability header is not valid")
	}
	if len(dah.KateCommits) < minExtendedSquareWidth {
		return fmt.Errorf(
			"minimum valid DataAvailabilityHeader has at least %d kate column commitments",
			minExtendedSquareWidth,
		)
	}
	if len(dah.KateCommits) > maxExtendedSquareWidth {
		return fmt.Errorf(
			"maximum valid DataAvailabilityHeader has at most %d kate column commitments",
			maxExtendedSquareWidth,
		)
	}
	if err := types.ValidateHash(dah.Hash()); err != nil {
		return fmt.Errorf("wrong hash: %v", err)
	}

	return nil
}

// IsZero returns true if the DataAvailabilityHeader is nil or has no commitments.
func (dah *DataAvailabilityHeader) IsZero() bool {
	if dah == nil {
		return true
	}
	return len(dah.KateCommits) == 0
}

// SquareSize returns the number of rows in the original data square.
func (dah *DataAvailabilityHeader) SquareSize() int {
	return len(dah.KateCommits) / 2
}

// MinDataAvailabilityHeader returns the minimum valid data availability header.
// It is equal to the data availability header for a block with one tail padding
// share.
func MinDataAvailabilityHeader() DataAvailabilityHeader {
	s := MinShares()
	eds, err := ExtendShares(s)
	if err != nil {
		panic(err)
	}
	dah, err := NewDataAvailabilityHeader(eds)
	if err != nil {
		panic(err)
	}
	return dah
}

// MinShares returns one tail-padded share.
func MinShares() [][]byte {
	return sharev4.ToBytes(squarev4.EmptySquare())
}
