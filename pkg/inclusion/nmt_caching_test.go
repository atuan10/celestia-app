package inclusion

import (
	"testing"

	"bytes"

	"github.com/celestiaorg/celestia-app/v8/pkg/appconsts"
	"github.com/celestiaorg/celestia-app/v8/pkg/da"
	"github.com/celestiaorg/celestia-app/v8/test/util/random"
	"github.com/celestiaorg/go-square/v4/share"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestColumnCommitmentVerifier(t *testing.T) {
	data := generateRandNamespacedRawData(16)
	eds, err := da.ConstructEDS(data, appconsts.Version, -1)
	require.NoError(t, err)

	dah, err := da.NewDataAvailabilityHeader(eds)
	require.NoError(t, err)

	verifier := NewColumnCommitmentVerifier()
	for column := range dah.KateCommits {
		err := verifier.Verify(dah, column, dah.KateCommits[column])
		require.NoError(t, err)
	}

	err = verifier.Verify(dah, 0, bytes.Repeat([]byte{0xFF}, len(dah.KateCommits[0])))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "column commitment mismatch")

	err = verifier.Verify(dah, len(dah.KateCommits), dah.KateCommits[0])
	require.Error(t, err)
	assert.Contains(t, err.Error(), "column exceeds range")
}

func TestColumnCommitmentVerifierWithProof(t *testing.T) {
	data := generateRandNamespacedRawData(16)
	eds, err := da.ConstructEDS(data, appconsts.Version, -1)
	require.NoError(t, err)

	dah, err := da.NewDataAvailabilityHeader(eds)
	require.NoError(t, err)

	column := 1
	proof, err := eds.BuildKateCommitmentProof(uint(column))
	require.NoError(t, err)

	verifier := NewColumnCommitmentVerifier()
	err = verifier.VerifyWithProof(dah, column, dah.KateCommits[column], proof)
	require.NoError(t, err)

	tamperedProof := *proof
	tamperedProof.ProofSet = append([][]byte(nil), proof.ProofSet...)
	tamperedProof.ProofSet[0] = append([]byte(nil), proof.ProofSet[0]...)
	tamperedProof.ProofSet[0][0] ^= 0x01
	err = verifier.VerifyWithProof(dah, column, dah.KateCommits[column], &tamperedProof)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "merkle proof does not match dah hash")
}

func generateRandNamespacedRawData(count int) (result [][]byte) {
	for range count {
		rawData := random.Bytes(share.ShareSize)
		namespace := share.RandomBlobNamespace().Bytes()
		copy(rawData, namespace)
		result = append(result, rawData)
	}

	return result
}
