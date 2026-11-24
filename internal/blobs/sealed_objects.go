package blobs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/Busnes-app/ky-primitives/s3"
	"github.com/Busnes-app/ky_server_base/internal/config"
)

var (
	errObjectIntegrity = errors.New("blobs: object integrity check failed")
	errObjectReceipt   = errors.New("blobs: object version receipt incomplete")
	errObjectConfig    = errors.New("blobs: invalid object adapter configuration")
)

// sealedObjects is the product's bounded ciphertext adapter over the shared S3
// transport. It is not a Backend: admission, durable write/erasure fencing,
// version accounting, replica cleanup and cache ownership must wrap these methods.
type sealedObjects struct {
	client   *s3.Client
	sealer   *Sealer
	scratch  string
	maxBytes int64
}

type sealedReceipt struct {
	PutResult
	versionID string
	etag      string
}

func newSealedObjects(client *s3.Client, key []byte, parent string, maxBytes int64) (*sealedObjects, error) {
	if client == nil {
		return nil, errObjectConfig
	}
	if maxBytes <= 0 || maxBytes > config.MaxAllowedUploadBytes {
		return nil, ErrTooLarge
	}
	sealer, err := NewSealer(key)
	if err != nil {
		return nil, err
	}
	scratch, err := os.MkdirTemp(parent, ".sealed-objects-*")
	if err != nil {
		return nil, err
	}
	return &sealedObjects{client: client, sealer: sealer, scratch: scratch, maxBytes: maxBytes}, nil
}

func (o *sealedObjects) close() error { return os.RemoveAll(o.scratch) }

func objectPath(tenantID, key string) (string, error) {
	if !config.IsCanonicalUUID(tenantID) || !ValidKey(key) {
		return "", ErrInvalidKey
	}
	return "orgs/" + tenantID + "/att/" + key, nil
}

// writeIfMatch requires the caller's durably recorded predecessor. It never
// creates an unconditional data write, retries one, or treats missing receipt
// metadata as proof that no remote write happened. The caller owns src and must
// ensure a blocked Read unblocks on cancellation.
func (o *sealedObjects) writeIfMatch(ctx context.Context, tenantID, key, predecessor string, src io.Reader) (sealedReceipt, error) {
	object, err := objectPath(tenantID, key)
	if err != nil {
		return sealedReceipt{}, err
	}
	if err := ctx.Err(); err != nil {
		return sealedReceipt{}, err
	}
	// Concurrent actors get separate local staging directories, even for one key.
	dir, err := os.MkdirTemp(o.scratch, "write-*")
	if err != nil {
		return sealedReceipt{}, err
	}
	defer os.RemoveAll(dir)
	stage, err := NewStore(dir)
	if err != nil {
		return sealedReceipt{}, err
	}
	meta, err := stage.Put(tenantID, key, src, o.maxBytes)
	if err != nil {
		return sealedReceipt{}, err
	}
	plain, err := os.ReadFile(filepath.Join(dir, key))
	if err != nil {
		return sealedReceipt{}, err
	}
	sealed, err := o.sealer.Seal(object, plain)
	if err != nil {
		return sealedReceipt{}, err
	}
	if err := ctx.Err(); err != nil {
		return sealedReceipt{}, err
	}
	remote, err := o.client.PutIfMatch(ctx, object, predecessor, bytes.NewReader(sealed), int64(len(sealed)))
	receipt := sealedReceipt{PutResult: meta, versionID: remote.VersionID, etag: remote.ETag}
	if err != nil {
		return receipt, err
	}
	if receipt.versionID == "" || receipt.etag == "" {
		return receipt, errObjectReceipt
	}
	return receipt, nil
}

// openVersion authenticates a complete, bounded exact version before creating a
// readable file. A caller cannot substitute current content for a missing version.
func (o *sealedObjects) openVersion(ctx context.Context, tenantID string, want sealedReceipt) (io.ReadSeekCloser, error) {
	object, err := objectPath(tenantID, want.Key)
	if err != nil {
		return nil, err
	}
	if want.versionID == "" || want.SizeBytes <= 0 || want.SizeBytes > o.maxBytes {
		return nil, errObjectIntegrity
	}
	body, meta, err := o.client.Get(ctx, object, want.versionID)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	wireSize := want.SizeBytes + SealedOverhead
	if meta.Size != wireSize {
		return nil, errObjectIntegrity
	}
	sealed, err := io.ReadAll(io.LimitReader(body, wireSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(sealed)) != wireSize {
		return nil, errObjectIntegrity
	}
	plain, err := o.sealer.Open(object, sealed)
	if err != nil {
		return nil, errObjectIntegrity
	}
	digest := sha256.Sum256(plain)
	if int64(len(plain)) != want.SizeBytes || hex.EncodeToString(digest[:]) != want.SHA256Hex {
		return nil, errObjectIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(o.scratch, "verified-*")
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(f.Name())
		}
	}()
	if _, err := f.Write(plain); err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	ok = true
	return &verifiedObject{File: f}, nil
}

type verifiedObject struct{ *os.File }

func (f *verifiedObject) Close() error {
	return errors.Join(f.File.Close(), os.Remove(f.File.Name()))
}
