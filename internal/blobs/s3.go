package blobs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Busnes-app/ky-primitives/s3"
	"github.com/Busnes-app/ky_server_base/internal/config"
)

var (
	errObjectIntegrity = errors.New("blobs: object integrity check failed")
	errObjectReceipt   = errors.New("blobs: object store returned no version (bucket versioning must be on)")
)

// s3OpTimeout bounds one object operation: Backend calls carry no request context.
const s3OpTimeout = 2 * time.Minute

// S3Store is the multi-mode Backend: each blob is one AES-256-GCM sealed object at
// cells/<cell>/orgs/<tenant_id>/att/<key> in a versioned bucket, where cell is the org's
// fixed KyIdentity home region (C1, C4), so cells can share a bucket and a deployment can
// split later without moving objects. Delete leaves the bucket's retained version; Erase and
// DeletePrefix remove every version.
type S3Store struct {
	client   *s3.Client
	sealer   *Sealer
	cellOf   func(tenantID string) (string, error)
	scratch  string
	maxBytes int64
}

var _ Backend = (*S3Store)(nil)

// NewS3Store needs a 32-byte seal key that never goes in the bucket, the org's cell
// (cellOf), and a private local scratch directory for staging uploads and verified downloads.
func NewS3Store(client *s3.Client, sealKey []byte, cellOf func(string) (string, error), scratch string, maxBytes int64) (*S3Store, error) {
	if client == nil || cellOf == nil || maxBytes <= 0 || maxBytes > config.MaxAllowedUploadBytes {
		return nil, errors.New("blobs: invalid object store configuration")
	}
	sealer, err := NewSealer(sealKey)
	if err != nil {
		return nil, err
	}
	if _, err := NewStore(scratch); err != nil {
		return nil, err
	}
	return &S3Store{client: client, sealer: sealer, cellOf: cellOf, scratch: scratch, maxBytes: maxBytes}, nil
}

func (o *S3Store) objectPath(tenantID, key string) (string, error) {
	if !ValidKey(key) {
		return "", ErrInvalidKey
	}
	prefix, err := o.orgPrefix(tenantID)
	if err != nil {
		return "", err
	}
	return prefix + "att/" + key, nil
}

// orgPrefix is the org's whole namespace. An org without a known cell has none.
func (o *S3Store) orgPrefix(tenantID string) (string, error) {
	if !config.IsCanonicalUUID(tenantID) {
		return "", ErrInvalidKey
	}
	cell, err := o.cellOf(tenantID)
	if err != nil {
		return "", err
	}
	if !config.ValidCell(cell) {
		return "", ErrInvalidKey
	}
	return "cells/" + cell + "/orgs/" + tenantID + "/", nil
}

// Put stages and sniffs the upload exactly as the disk store does, seals it and writes it
// once with If-None-Match (keys are never reused). When the write may have landed but gave
// no usable receipt, every version of the key is erased, so no unaccounted object remains.
func (o *S3Store) Put(tenantID, key string, r io.Reader, maxBytes int64) (PutResult, error) {
	object, err := o.objectPath(tenantID, key)
	if err != nil {
		return PutResult{}, err
	}
	if maxBytes > o.maxBytes {
		maxBytes = o.maxBytes
	}
	// Each upload stages in its own directory, so concurrent uploads never share a file.
	dir, err := os.MkdirTemp(o.scratch, ".upload-")
	if err != nil {
		return PutResult{}, err
	}
	defer os.RemoveAll(dir)
	stage, err := NewStore(dir)
	if err != nil {
		return PutResult{}, err
	}
	meta, err := stage.Put(tenantID, key, r, maxBytes)
	if err != nil {
		return PutResult{}, err
	}
	plain, err := os.ReadFile(filepath.Join(dir, key))
	if err != nil {
		return PutResult{}, err
	}
	sealed, err := o.sealer.Seal(object, plain)
	if err != nil {
		return PutResult{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), s3OpTimeout)
	defer cancel()
	remote, err := o.client.PutIfAbsent(ctx, object, bytes.NewReader(sealed), int64(len(sealed)))
	// "null" is what a bucket with versioning suspended answers: no version to retain.
	if err == nil && (remote.VersionID == "" || remote.VersionID == "null") {
		err = errObjectReceipt
	}
	if err != nil {
		if !errors.Is(err, s3.ErrAlreadyExists) {
			if eraseErr := o.Erase(tenantID, key); eraseErr != nil {
				log.Printf("[ATTACHMENTS] object %s may be orphaned after a failed write: %v", key, eraseErr)
			}
		}
		return PutResult{}, err
	}
	meta.VersionID = remote.VersionID
	return meta, nil
}

// Open fetches the whole current version and verifies its GCM tag, bound to this org and key,
// before any byte is readable. The object must be exactly sizeBytes (the attachment's recorded
// size, at most the fixed hard maximum) plus the seal: a lowered upload limit restricts new
// writes, never existing files. It serves ranges from a private local copy that Close removes.
func (o *S3Store) Open(tenantID, key string, sizeBytes int64) (io.ReadSeekCloser, int64, error) {
	object, err := o.objectPath(tenantID, key)
	if err != nil {
		return nil, 0, err
	}
	if sizeBytes <= 0 || sizeBytes > config.MaxAllowedUploadBytes {
		return nil, 0, errObjectIntegrity
	}
	ctx, cancel := context.WithTimeout(context.Background(), s3OpTimeout)
	defer cancel()
	body, meta, err := o.client.Get(ctx, object, "")
	if err != nil {
		return nil, 0, err // s3.ErrNotFound is os.ErrNotExist
	}
	defer body.Close()
	want := sizeBytes + SealedOverhead
	if meta.Size != want {
		return nil, 0, errObjectIntegrity
	}
	sealed, err := io.ReadAll(io.LimitReader(body, want+1))
	if err != nil {
		return nil, 0, err
	}
	if int64(len(sealed)) != meta.Size {
		return nil, 0, errObjectIntegrity
	}
	plain, err := o.sealer.Open(object, sealed)
	if err != nil {
		return nil, 0, errObjectIntegrity
	}
	f, err := createVerified(o.scratch, ".verified-")
	if err != nil {
		return nil, 0, err
	}
	if _, err = f.Write(plain); err == nil {
		_, err = f.Seek(0, io.SeekStart)
	}
	if err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, 0, err
	}
	return &verifiedObject{File: f}, int64(len(plain)), nil
}

// createVerified makes the private copy a download is served from (a test seam).
var createVerified = os.CreateTemp

type verifiedObject struct{ *os.File }

func (f *verifiedObject) Close() error {
	return errors.Join(f.File.Close(), os.Remove(f.File.Name()))
}

// Delete is a user's own delete: it hides the current version and the bucket keeps the
// previous one as its backup copy, which the store keeps charged to the org (§9.4).
func (o *S3Store) Delete(tenantID, key string) error {
	object, err := o.objectPath(tenantID, key)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), s3OpTimeout)
	defer cancel()
	_, err = o.client.Delete(ctx, object, "")
	if errors.Is(err, s3.ErrNotFound) {
		return nil
	}
	return err
}

// Erase removes every version and delete marker of one object (erasure, purge, rollback).
func (o *S3Store) Erase(tenantID, key string) error {
	object, err := o.objectPath(tenantID, key)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), s3OpTimeout)
	defer cancel()
	return o.client.DeleteAllVersions(ctx, object)
}

// DeletePrefix removes every version of every object of one org, orphans included.
func (o *S3Store) DeletePrefix(tenantID string) error {
	prefix, err := o.orgPrefix(tenantID)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	return o.client.DeletePrefix(ctx, prefix)
}

// SweepStaleTemps removes staging directories and verified copies a crash left behind.
func (o *S3Store) SweepStaleTemps(olderThan time.Duration) int {
	entries, err := os.ReadDir(o.scratch)
	if err != nil {
		return 0
	}
	cutoff := time.Now().Add(-olderThan)
	removed := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, ".upload-") && !strings.HasPrefix(name, ".verified-") {
			continue
		}
		if info, err := e.Info(); err != nil || info.ModTime().After(cutoff) {
			continue
		}
		if os.RemoveAll(filepath.Join(o.scratch, name)) == nil {
			removed++
		}
	}
	return removed
}
