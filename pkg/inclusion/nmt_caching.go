package inclusion

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	rsmt2d "github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d"
	"github.com/celestiaorg/celestia-app/v8/pkg/da"
	"github.com/celestiaorg/merkletree"
)

// ColumnCommitmentVerifier verifies that a commitment matches the commitment
// stored in a DAH for the requested column.
type ColumnCommitmentVerifier struct{}

// NewColumnCommitmentVerifier returns a stateless verifier.
func NewColumnCommitmentVerifier() *ColumnCommitmentVerifier {
	return &ColumnCommitmentVerifier{}
}

// Verify returns an error if the commitment does not match the commitment for
// the requested column in the DAH.
func (v *ColumnCommitmentVerifier) Verify(dah da.DataAvailabilityHeader, column int, commitment []byte) error {
	if column < 0 {
		return fmt.Errorf("column index cannot be negative: %d", column)
	}
	if len(dah.KateCommits) == 0 {
		return fmt.Errorf("data availability header has no kate commitments")
	}
	if column >= len(dah.KateCommits) {
		return fmt.Errorf("column exceeds range of dah commitments: max %d got %d", len(dah.KateCommits)-1, column)
	}
	if !bytes.Equal(dah.KateCommits[column], commitment) {
		return fmt.Errorf("column commitment mismatch at index %d", column)
	}
	return nil
}

// VerifyWithProof checks that a column commitment matches the DAH and that its
// Merkle proof resolves to the DAH hash.
func (v *ColumnCommitmentVerifier) VerifyWithProof(dah da.DataAvailabilityHeader, column int, commitment []byte, proof *rsmt2d.KateMerkleProof) error {
	if err := v.Verify(dah, column, commitment); err != nil {
		return err
	}
	if proof == nil || len(proof.ProofSet) == 0 {
		return fmt.Errorf("merkle proof is empty")
	}
	if ok := merkletree.VerifyProof(sha256.New(), dah.Hash(), proof.ProofSet, proof.ProofIndex, proof.NumLeaves); !ok {
		return fmt.Errorf("merkle proof does not match dah hash")
	}
	return nil
}
