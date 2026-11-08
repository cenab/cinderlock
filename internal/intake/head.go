package intake

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
	"golang.org/x/sys/unix"
)

type Head struct {
	spec.Header
	ManifestDigest string `json:"manifestDigest"`
	BundleDigest   string `json:"bundleDigest"`
	ReceiptDigest  string `json:"receiptDigest"`
	Sequence       int64  `json:"sequence"`
}

func readHead(path string) (Head, error) {
	var head Head
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return head, err
	}
	f := os.NewFile(uintptr(fd), "")
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return head, err
	}
	if !stat.Mode().IsRegular() || stat.Mode().Perm() != 0600 || stat.Size() > MaxReceiptBytes {
		return head, errors.New("custody head must be a bounded private regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxReceiptBytes+1))
	if err != nil {
		return head, err
	}
	if len(data) > MaxReceiptBytes {
		return head, errors.New("custody head exceeds size limit")
	}
	if err = spec.Decode(data, &head); err != nil {
		return head, err
	}
	if err = spec.ValidateHeader(head.Header, "CustodyHead"); err != nil {
		return head, err
	}
	if !spec.ValidDigest(head.ManifestDigest) || !spec.ValidDigest(head.BundleDigest) || !spec.ValidDigest(head.ReceiptDigest) || head.Sequence <= 0 || head.Sequence > MaxChainReceipts {
		return head, errors.New("custody head identity is invalid")
	}
	return head, nil
}

func lockHead(ctx context.Context, path string) (func(), error) {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return nil, err
	}
	stat, err := os.Lstat(parent)
	if err != nil {
		return nil, err
	}
	if !stat.IsDir() || stat.Mode().Perm()&0022 != 0 {
		return nil, errors.New("custody head directory must not be a symlink or group/world writable")
	}
	fd, err := unix.Open(path+".lock", unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "")
	stat, err = f.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Mode().Perm() != 0600 {
		f.Close()
		return nil, errors.New("custody head lock must be a private regular file")
	}
	for {
		if err := ctx.Err(); err != nil {
			f.Close()
			return nil, err
		}
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = f.Close() }, nil
		}
		if err != unix.EWOULDBLOCK && err != unix.EAGAIN {
			f.Close()
			return nil, err
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			f.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func writeHead(path string, head Head) error {
	data, err := spec.Canonical(head)
	if err != nil {
		return err
	}
	parent := filepath.Dir(path)
	f, err := os.CreateTemp(parent, ".custody-head-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	directory, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// AnchorReceipt verifies and advances exactly one private local head. Concurrent
// children of the same head cannot both advance it. It is not a fleet ledger.
func AnchorReceipt(ctx context.Context, headPath, bundlePath string, vendor spec.TrustPolicy, m Manifest, receipt SignedReceipt, policy CustodyPolicy, previous string, now func() time.Time) (Verification, error) {
	if err := ctx.Err(); err != nil {
		return Verification{}, err
	}
	if now == nil {
		now = time.Now
	}
	if err := VerifyManifest(ctx, bundlePath, vendor, m); err != nil {
		return Verification{}, err
	}
	unlock, err := lockHead(ctx, headPath)
	if err != nil {
		return Verification{}, err
	}
	defer unlock()
	verified, err := verifyReceipt(m, receipt, policy, vendor, previous, now())
	if err != nil {
		return verified, err
	}
	old, err := readHead(headPath)
	if errors.Is(err, os.ErrNotExist) {
		if previous != Genesis || verified.Sequence != 1 {
			return verified, errors.New("missing custody head requires explicit genesis")
		}
	} else if err != nil {
		return verified, err
	} else if old.Metadata != m.Metadata || old.ManifestDigest != verified.ManifestDigest || old.BundleDigest != verified.BundleDigest || old.ReceiptDigest != previous || old.Sequence+1 != verified.Sequence {
		return verified, errors.New("custody head changed, belongs to another manifest, or would fork/replay")
	}
	next := Head{Header: spec.NewHeader("CustodyHead"), ManifestDigest: verified.ManifestDigest, BundleDigest: verified.BundleDigest, ReceiptDigest: verified.ReceiptDigest, Sequence: verified.Sequence}
	next.Metadata = m.Metadata
	if err := ctx.Err(); err != nil {
		return verified, err
	}
	if err = writeHead(headPath, next); err != nil {
		return verified, err
	}
	verified.Anchored = true
	verified.Notice = "Scoped signature and exact manifest/bundle binding verified; the private local head advanced atomically. Custodian labels are declared. Physical custody and human approval are unobserved; no execution admission is granted."
	return verified, nil
}
