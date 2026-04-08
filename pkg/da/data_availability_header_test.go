package da

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	rsmt2d "github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d"
	"github.com/celestiaorg/celestia-app/v8/pkg/appconsts"
	appconstsv5 "github.com/celestiaorg/celestia-app/v8/pkg/appconsts/v5"
	"github.com/celestiaorg/celestia-app/v8/pkg/wrapper"
	fibretypes "github.com/celestiaorg/celestia-app/v8/x/fibre/types"
	sharev2 "github.com/celestiaorg/go-square/v2/share"
	squarev4 "github.com/celestiaorg/go-square/v4"
	sh "github.com/celestiaorg/go-square/v4/share"
	gotx "github.com/celestiaorg/go-square/v4/tx"
	"github.com/cosmos/btcutil/bech32"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cosmostx "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNilDataAvailabilityHeaderHashDoesntCrash(t *testing.T) {
	// This follows RFC-6962, i.e. `echo -n '' | sha256sum`
	emptyBytes := []byte{
		0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8,
		0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
		0x78, 0x52, 0xb8, 0x55,
	}

	assert.Equal(t, emptyBytes, (*DataAvailabilityHeader)(nil).Hash())
	assert.Equal(t, emptyBytes, new(DataAvailabilityHeader).Hash())
}

// TestMinDataAvailabilityHeader tests the minimum valid data availability header.
//
// This test verifies that MinDataAvailabilityHeader() produces a deterministic hash
// that matches the expected value. The expected hash is generated through the following process:
//
// 1. Create minimum shares: MinShareCount (1) tail padding shares are created
// 2. Extend shares: The single share is extended using Reed-Solomon encoding to create a 2x2 extended data square
// 3. Extract roots: Row and column merkle roots are computed from the extended square:
//   - 2 row roots (one for each row of the extended square)
//   - 2 column roots (one for each column of the extended square)
//
// 4. Compute hash: A binary merkle tree is built from all Kate column commitments
// to produce the final data availability header hash.
//
// The expectedHash below (0xbe61258b...) represents the merkle root of Kate
// column commitments from a 2x2 extended data square containing one tail padding share.
// This hash is deterministic and will always be the same for the minimum data availability header
// since it represents the smallest possible valid data square in the Celestia network.
func TestMinDataAvailabilityHeader(t *testing.T) {
	dah := MinDataAvailabilityHeader()
	// Expected hash generated from merkle root of all Kate column commitments.
	expectedHash := []byte{0xbe, 0x61, 0x25, 0x8b, 0xd7, 0xc7, 0x75, 0x21, 0x8d, 0x70, 0x2c, 0x78, 0xfe, 0xe3, 0x5c, 0x2b, 0x2a, 0xf8, 0x34, 0x6e, 0x60, 0x93, 0x49, 0xaf, 0x35, 0x14, 0x3e, 0x29, 0x61, 0x9, 0x2a, 0x15}
	require.Equal(t, expectedHash, dah.hash)
	require.NoError(t, dah.ValidateBasic())
}

type (
	extendFunc    = func([][]byte) (*rsmt2d.ExtendedDataSquare, error)
	constructFunc = func(txs [][]byte, appVersion uint64, maxSquareSize int) (*rsmt2d.ExtendedDataSquare, error)
)

// extendSharesWithPool works exactly the same as ExtendShares,
// but it uses treePool to reuse the allocs.
func extendSharesWithPool(s [][]byte) (*rsmt2d.ExtendedDataSquare, error) {
	treePool, err := wrapper.DefaultPreallocatedTreePool(512)
	if err != nil {
		return nil, err
	}
	return ExtendSharesWithTreePool(s, treePool)
}

// constructEDSWithPool works exactly the same as ConstructEDS,
// but it uses treePool to reuse the allocs.
func constructEDSWithPool(txs [][]byte, appVersion uint64, maxSquareSize int) (*rsmt2d.ExtendedDataSquare, error) {
	treePool, err := wrapper.DefaultPreallocatedTreePool(512)
	if err != nil {
		return nil, err
	}
	return ConstructEDSWithTreePool(txs, appVersion, maxSquareSize, treePool)
}

func TestMinDataAvailabilityHeaderBackwardsCompatibility(t *testing.T) {
	for _, extendShares := range []extendFunc{
		extendSharesWithPool,
		ExtendShares,
	} {
		dahv4 := MinDataAvailabilityHeader()
		shareV2 := sharev2.ToBytes(sharev2.TailPaddingShares(appconsts.MinShareCount))
		eds, err := extendShares(shareV2)
		require.NoError(t, err)
		dahV2, err := NewDataAvailabilityHeader(eds)
		require.NoError(t, err)
		require.Equal(t, dahv4.hash, dahV2.hash)
	}
}

func TestNewDataAvailabilityHeader(t *testing.T) {
	type test struct {
		name         string
		expectedHash []byte
		squareSize   uint64
		shares       [][]byte
	}

	tests := []test{
		{
			name:         "typical",
			expectedHash: []byte{0x34, 0x69, 0x18, 0x28, 0x75, 0x8c, 0xf, 0x8, 0x44, 0xc, 0xdb, 0x5f, 0x1d, 0x7e, 0xc4, 0xe4, 0xbd, 0xd5, 0x5d, 0xb, 0x2e, 0x72, 0x3, 0x64, 0x3d, 0xd1, 0xb7, 0x53, 0xed, 0x15, 0x59, 0xef},
			squareSize:   2,
			shares:       generateShares(2 * 2),
		},
		{
			name:         "max square size",
			expectedHash: []byte{0xcf, 0x51, 0x75, 0xba, 0xdc, 0x48, 0x61, 0xb0, 0x5c, 0xba, 0x2b, 0xdd, 0xa8, 0x7f, 0xe5, 0xbe, 0xfa, 0x94, 0x77, 0xb8, 0x14, 0xe7, 0x6, 0xaf, 0xc6, 0x91, 0x9e, 0x88, 0xbb, 0x52, 0x7c, 0x5e},
			squareSize:   uint64(appconsts.SquareSizeUpperBound),
			shares:       generateShares(appconsts.SquareSizeUpperBound * appconsts.SquareSizeUpperBound),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, extendShares := range []extendFunc{
				extendSharesWithPool,
				ExtendShares,
			} {
				eds, err := extendShares(tt.shares)
				require.NoError(t, err)
				got, err := NewDataAvailabilityHeader(eds)
				require.NoError(t, err)
				require.Equal(t, tt.squareSize*2, uint64(len(got.KateCommits)))
				require.Equal(t, tt.expectedHash, got.hash)
			}
		})
	}
}

func TestExtendShares(t *testing.T) {
	type test struct {
		name        string
		expectedErr bool
		shares      [][]byte
	}

	tests := []test{
		{
			name:        "too large square size",
			expectedErr: true,
			shares:      generateShares((appconsts.SquareSizeUpperBound + 1) * (appconsts.SquareSizeUpperBound + 1)),
		},
		{
			name:        "invalid number of shares",
			expectedErr: true,
			shares:      generateShares(5),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, extendShares := range []extendFunc{
				extendSharesWithPool,
				ExtendShares,
			} {
				_, err := extendShares(tt.shares)
				if tt.expectedErr {
					require.NotNil(t, err)
				} else {
					require.NoError(t, err)
				}
			}
		})
	}
}

func TestDataAvailabilityHeaderProtoConversion(t *testing.T) {
	for _, extendShares := range []extendFunc{
		extendSharesWithPool,
		ExtendShares,
	} {
		testDataAvailabilityHeaderProtoConversion(t, extendShares)
	}
}

func testDataAvailabilityHeaderProtoConversion(t *testing.T, extendShares func([][]byte) (*rsmt2d.ExtendedDataSquare, error)) {
	type test struct {
		name string
		dah  DataAvailabilityHeader
	}

	shares := generateShares(appconsts.SquareSizeUpperBound * appconsts.SquareSizeUpperBound)
	eds, err := extendShares(shares)
	require.NoError(t, err)
	bigdah, err := NewDataAvailabilityHeader(eds)
	require.NoError(t, err)

	tests := []test{
		{
			name: "min",
			dah:  MinDataAvailabilityHeader(),
		},
		{
			name: "max",
			dah:  bigdah,
		},
	}

	for _, tt := range tests {
		pdah, err := tt.dah.ToProto()
		require.NoError(t, err)
		resDah, err := DataAvailabilityHeaderFromProto(pdah)
		require.NoError(t, err)
		resDah.Hash() // calc the hash to make the comparisons fair
		require.Equal(t, tt.dah, *resDah, tt.name)
	}
}

func Test_DAHValidateBasic(t *testing.T) {
	for _, extendShares := range []extendFunc{
		extendSharesWithPool,
		ExtendShares,
	} {
		testDAHValidateBasic(t, extendShares)
	}
}

func testDAHValidateBasic(t *testing.T, extendShares func([][]byte) (*rsmt2d.ExtendedDataSquare, error)) {
	type test struct {
		name      string
		dah       DataAvailabilityHeader
		expectErr bool
		errStr    string
	}

	maxSize := appconsts.SquareSizeUpperBound * appconsts.SquareSizeUpperBound

	shares := generateShares(maxSize)
	eds, err := extendShares(shares)
	require.NoError(t, err)
	bigdah, err := NewDataAvailabilityHeader(eds)
	require.NoError(t, err)

	// make a mutant dah that has too many roots
	var tooBigDah DataAvailabilityHeader
	tooBigDah.KateCommits = make([][]byte, maxSize)
	copy(tooBigDah.KateCommits, bigdah.KateCommits)
	tooBigDah.KateCommits = append(tooBigDah.KateCommits, bytes.Repeat([]byte{1}, 32))
	// make a mutant dah that has too few roots
	var tooSmallDah DataAvailabilityHeader
	tooSmallDah.KateCommits = [][]byte{bytes.Repeat([]byte{2}, 32)}
	// use a bad hash
	badHashDah := MinDataAvailabilityHeader()
	badHashDah.hash = []byte{1, 2, 3, 4}

	tests := []test{
		{
			name: "min",
			dah:  MinDataAvailabilityHeader(),
		},
		{
			name: "max",
			dah:  bigdah,
		},
		{
			name:      "too big dah",
			dah:       tooBigDah,
			expectErr: true,
			errStr:    "maximum valid DataAvailabilityHeader has at most",
		},
		{
			name:      "too small dah",
			dah:       tooSmallDah,
			expectErr: true,
			errStr:    "minimum valid DataAvailabilityHeader has at least",
		},
		{
			name:      "bad hash",
			dah:       badHashDah,
			expectErr: true,
			errStr:    "wrong hash",
		},
	}

	for _, tt := range tests {
		err := tt.dah.ValidateBasic()
		if tt.expectErr {
			require.True(t, strings.Contains(err.Error(), tt.errStr), tt.name)
			require.Error(t, err)
			continue
		}
		require.NoError(t, err)
	}
}

func TestSquareSize(t *testing.T) {
	type testCase struct {
		name string
		dah  DataAvailabilityHeader
		want int
	}

	testCases := []testCase{
		{
			name: "min data availability header has an original square size of 1",
			dah:  MinDataAvailabilityHeader(),
			want: 1,
		},
		{
			name: "max data availability header has an original square size of default square size upper bound",
			dah:  maxDataAvailabilityHeader(t),
			want: appconsts.SquareSizeUpperBound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.dah.SquareSize()
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestConstructEDS_Versions(t *testing.T) {
	minAppVersion := uint64(0)
	maxAppVersion := appconsts.Version + 1 // even future versions won't error and assume compatibility with v4
	for appVersion := minAppVersion; appVersion <= maxAppVersion; appVersion++ {
		t.Run(fmt.Sprintf("app version %d", appVersion), func(t *testing.T) {
			for _, constructEDS := range []constructFunc{
				constructEDSWithPool,
				ConstructEDS,
			} {
				shares := generateShares(4)
				maxSquareSize := -1
				eds, err := constructEDS(shares, appVersion, maxSquareSize)
				if appVersion == 0 {
					require.Error(t, err)
					require.Nil(t, eds)
				} else {
					require.NoError(t, err)
					require.NotNil(t, eds)
				}
			}
		})
	}
}

func TestConstructEDS_SquareSize(t *testing.T) {
	type testCase struct {
		name         string
		appVersion   uint64
		maxSquare    int
		expectedSize int
	}
	testCases := []testCase{
		{
			name:         "v5 version with custom square size",
			appVersion:   appconstsv5.Version,
			maxSquare:    4,
			expectedSize: 4,
		},
		{
			name:         "v5 version with default square size",
			appVersion:   appconstsv5.Version,
			maxSquare:    -1,
			expectedSize: appconstsv5.SquareSizeUpperBound,
		},
		{
			name:         "latest version with custom square size",
			appVersion:   appconsts.Version,
			maxSquare:    8,
			expectedSize: 8,
		},
		{
			name:         "latest version with default square size",
			appVersion:   appconsts.Version,
			maxSquare:    -1,
			expectedSize: appconsts.SquareSizeUpperBound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, construct := range []constructFunc{
				constructEDSWithPool,
				ConstructEDS,
			} {
				txLength := sh.AvailableBytesFromCompactShares((tc.expectedSize * tc.expectedSize) - 1)
				tx := bytes.Repeat([]byte{0x1}, txLength)
				eds, err := construct([][]byte{tx}, tc.appVersion, tc.maxSquare)
				require.NoError(t, err)
				require.NotNil(t, eds)
				// The EDS width should be 2*expectedSize
				require.Equal(t, tc.expectedSize*2, int(eds.Width()))
			}
		})
	}
}

// generateShares generates count number of shares with a constant namespace and
// share contents.
func generateShares(count int) (shares [][]byte) {
	ns1 := sh.MustNewV0Namespace(bytes.Repeat([]byte{1}, sh.NamespaceVersionZeroIDSize))

	for range count {
		share := generateShare(ns1.Bytes())
		shares = append(shares, share)
	}
	sortByteArrays(shares)
	return shares
}

func generateShare(namespace []byte) (share []byte) {
	remainder := bytes.Repeat([]byte{0xFF}, sh.ShareSize-len(namespace))
	share = append(share, namespace...)
	share = append(share, remainder...)
	return share
}

func sortByteArrays(arr [][]byte) {
	sort.Slice(arr, func(i, j int) bool {
		return bytes.Compare(arr[i], arr[j]) < 0
	})
}

// TestConstructEDS_RealBlocks verifies that ConstructEDS produces a data
// availability header whose hash matches the on-chain data hash for real
// blocks from Celestia mainnet and Mocha testnet. This ensures that the
// go-square version used for each app version is correct and consensus-compatible.
func TestConstructEDS_RealBlocks(t *testing.T) {
	files := []string{
		"testdata/mainnet_block_10126899.json", // app version 6, Celestia mainnet
		"testdata/mocha_block_10383867.json",   // app version 7, Mocha testnet
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		require.NoError(t, err)

		var block struct {
			Height     int64    `json:"height"`
			AppVersion uint64   `json:"app_version"`
			DataHash   string   `json:"data_hash"`
			SquareSize int      `json:"square_size"`
			Txs        []string `json:"txs"`
		}
		require.NoError(t, json.Unmarshal(data, &block))

		// Decode base64 txs.
		txs := make([][]byte, len(block.Txs))
		for i, b64 := range block.Txs {
			txs[i], err = base64.StdEncoding.DecodeString(b64)
			require.NoError(t, err)
		}

		// Decode expected data hash.
		expectedHash, err := hex.DecodeString(block.DataHash)
		require.NoError(t, err)

		t.Run(fmt.Sprintf("height_%d_v%d", block.Height, block.AppVersion), func(t *testing.T) {
			for _, construct := range []constructFunc{
				constructEDSWithPool,
				ConstructEDS,
			} {
				eds, err := construct(txs, block.AppVersion, block.SquareSize)
				require.NoError(t, err)
				require.NotNil(t, eds)

				dah, err := NewDataAvailabilityHeader(eds)
				require.NoError(t, err)
				require.Equal(t, expectedHash, dah.Hash(),
					"data hash mismatch for block %d (app version %d)", block.Height, block.AppVersion)
			}
		})
	}
}

func TestConstructEDS_WithFibreTx(t *testing.T) {
	fibreTx := buildMsgPayForFibreTxBytes(t)

	type testCase struct {
		name string
		txs  [][]byte
	}

	testCases := []testCase{
		{
			name: "fibre tx only",
			txs:  [][]byte{fibreTx},
		},
		{
			name: "normal tx and fibre tx",
			// squarev4.Construct requires ordering: normal txs, then blob txs, then fibre txs
			txs: [][]byte{bytes.Repeat([]byte{0x01}, 200), fibreTx},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Verify that the data square contains PayForFibre namespace shares.
			square, err := squarev4.Construct(tc.txs, appconsts.SquareSizeUpperBound, appconsts.SubtreeRootThreshold)
			require.NoError(t, err)
			pffRange := sh.GetShareRangeForNamespace(square, sh.PayForFibreNamespace)
			require.False(t, pffRange.IsEmpty(), "expected PayForFibreNamespace shares in square")

			t.Run("without pool", func(t *testing.T) {
				eds, err := ConstructEDS(tc.txs, appconsts.Version, -1)
				require.NoError(t, err)
				require.NotNil(t, eds)
			})

			t.Run("with pool", func(t *testing.T) {
				eds, err := constructEDSWithPool(tc.txs, appconsts.Version, -1)
				require.NoError(t, err)
				require.NotNil(t, eds)
			})
		})
	}
}

func TestDAHComputationFlowLogs(t *testing.T) {
	appVersion := appconsts.Version
	maxSquareSize := -1

	fibreTx := buildMsgPayForFibreTxBytes(t)
	normalTx := bytes.Repeat([]byte{0xAB}, 180)
	txs := [][]byte{normalTx, fibreTx}

	t.Logf("[INPUT] appVersion=%d maxSquareSize=%d txCount=%d", appVersion, maxSquareSize, len(txs))
	for i, tx := range txs {
		prefixLen := 16
		if len(tx) < prefixLen {
			prefixLen = len(tx)
		}
		t.Logf("[INPUT] tx[%d] len=%d prefix=%s", i, len(tx), strings.ToUpper(hex.EncodeToString(tx[:prefixLen])))
	}

	eds, err := ConstructEDS(txs, appVersion, maxSquareSize)
	require.NoError(t, err)
	require.NotNil(t, eds)

	flattened := eds.Flattened()
	t.Logf("[EDS] width=%d originalSquareSize=%d flattenedCells=%d", eds.Width(), eds.Width()/2, len(flattened))

	if kateCols, kateErr := eds.KateCols(); kateErr != nil {
		t.Logf("[EDS] KateCols before DAH generation: unavailable (%v)", kateErr)
	} else {
		t.Logf("[EDS] KateCols before DAH generation: count=%d", len(kateCols))
	}

	dah, err := NewDataAvailabilityHeader(eds)
	require.NoError(t, err)

	if kateCols, kateErr := eds.KateCols(); kateErr != nil {
		t.Fatalf("KateCols should be available after DAH generation: %v", kateErr)
	} else {
		t.Logf("[EDS] KateCols after DAH generation: count=%d", len(kateCols))
	}

	t.Logf("[DAH] kateCommits=%d squareSize=%d", len(dah.KateCommits), dah.SquareSize())
	maxLogs := 3
	if len(dah.KateCommits) < maxLogs {
		maxLogs = len(dah.KateCommits)
	}
	for i := 0; i < maxLogs; i++ {
		t.Logf("[DAH] kateCommits[%d]=%s", i, strings.ToUpper(hex.EncodeToString(dah.KateCommits[i])))
	}

	h := dah.Hash()
	t.Logf("[DAH] hash=%s", strings.ToUpper(hex.EncodeToString(h)))

	require.NoError(t, dah.ValidateBasic())
	require.False(t, dah.IsZero())
	require.Equal(t, int(eds.Width()/2), dah.SquareSize())
}

// buildMsgPayForFibreTxBytes constructs Cosmos SDK Tx proto bytes containing a
// single MsgPayForFibre message. This replicates the pattern from
// go-square/v4/internal/test.BuildMsgPayForFibreTxBytes which is not importable.
func buildMsgPayForFibreTxBytes(t *testing.T) []byte {
	t.Helper()
	ns := sh.MustNewV0Namespace(bytes.Repeat([]byte{1}, sh.NamespaceVersionZeroIDSize))
	signerRaw := bytes.Repeat([]byte{0xAA}, sh.SignerSize)
	signer, err := bech32.EncodeFromBase256("celestia", signerRaw)
	require.NoError(t, err)
	commitment := bytes.Repeat([]byte{0xFF}, sh.FibreCommitmentSize)

	msg := &fibretypes.MsgPayForFibre{
		Signer: signer,
		PaymentPromise: fibretypes.PaymentPromise{
			Namespace:   ns.Bytes(),
			BlobVersion: fibretypes.BlobVersionZero,
			Commitment:  commitment,
		},
	}

	anyMsg, err := codectypes.NewAnyWithValue(msg)
	require.NoError(t, err)
	// Verify the cosmos-sdk derived TypeURL matches the constant that
	// TryParseFibreTx checks when parsing fibre transactions.
	require.Equal(t, gotx.MsgPayForFibreTypeURL, anyMsg.TypeUrl,
		"cosmos-sdk TypeURL must match the constant that TryParseFibreTx checks")

	body := &cosmostx.TxBody{
		Messages: []*codectypes.Any{anyMsg},
	}
	tx := &cosmostx.Tx{Body: body}
	txBytes, err := tx.Marshal()
	require.NoError(t, err)
	return txBytes
}

// maxDataAvailabilityHeader returns a DataAvailabilityHeader with the maximum square
// size. This should only be used for testing.
func maxDataAvailabilityHeader(t *testing.T) (dah DataAvailabilityHeader) {
	return maxDataAvailabilityHeaderWithExtendShares(t, ExtendShares)
}

// maxDataAvailabilityHeaderWithExtendShares returns a DataAvailabilityHeader with the maximum square
// size using the provided extendShares function. This should only be used for testing.
func maxDataAvailabilityHeaderWithExtendShares(t *testing.T, extendShares func([][]byte) (*rsmt2d.ExtendedDataSquare, error)) (dah DataAvailabilityHeader) {
	shares := generateShares(appconsts.SquareSizeUpperBound * appconsts.SquareSizeUpperBound)

	eds, err := extendShares(shares)
	require.NoError(t, err)

	dah, err = NewDataAvailabilityHeader(eds)
	require.NoError(t, err)

	return dah
}
