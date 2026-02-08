//go:build linux

package bpfloader

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/sandbox"
	bpfdata "github.com/BakeLens/crust/internal/sandbox/bpf"
)

const maxFilename = 256

var bpfLog = logger.New("bpf")

// denyEvent matches the C struct deny_event in deny.bpf.c.
type denyEvent struct {
	PID      uint32
	RuleID   uint32
	Ino      uint64
	Filename [maxFilename]byte
}

// bpfMaps holds references to all BPF maps after loading.
type bpfMaps struct {
	DeniedFilenames  *ebpf.Map
	DeniedInodes     *ebpf.Map
	AllowedFilenames *ebpf.Map
	Events           *ebpf.Map
	TargetPids       *ebpf.Map
}

// BPFLoader manages the lifecycle of the BPF LSM program and its maps.
type BPFLoader struct {
	maps   bpfMaps
	prog   *ebpf.Program
	lsmLnk link.Link
	reader *ringbuf.Reader
	mu     sync.Mutex
	closed bool

	onViolation func(sandbox.BPFViolation)
	stopCh      chan struct{}
}

// NewBPFLoader loads the BPF LSM program and attaches it to the file_open hook.
// Requires CAP_BPF and CAP_SYS_ADMIN capabilities.
func NewBPFLoader() (*BPFLoader, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfdata.DenyBytes()))
	if err != nil {
		return nil, fmt.Errorf("load BPF spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("BPF verifier error: %w\n%+v", err, ve)
		}
		return nil, fmt.Errorf("create BPF collection: %w", err)
	}

	prog := coll.Programs["deny_file_open"]
	if prog == nil {
		coll.Close()
		return nil, fmt.Errorf("deny_file_open program not found in collection")
	}

	maps := bpfMaps{
		DeniedFilenames:  coll.Maps["denied_filenames"],
		DeniedInodes:     coll.Maps["denied_inodes"],
		AllowedFilenames: coll.Maps["allowed_filenames"],
		Events:           coll.Maps["events"],
		TargetPids:       coll.Maps["target_pids"],
	}

	// Attach to LSM file_open hook
	lsmLnk, err := link.AttachLSM(link.LSMOptions{
		Program: prog,
	})
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attach LSM: %w", err)
	}

	// Create ring buffer reader for violation events
	rd, err := ringbuf.NewReader(maps.Events)
	if err != nil {
		lsmLnk.Close()
		coll.Close()
		return nil, fmt.Errorf("create ringbuf reader: %w", err)
	}

	l := &BPFLoader{
		maps:   maps,
		prog:   prog,
		lsmLnk: lsmLnk,
		reader: rd,
		stopCh: make(chan struct{}),
	}

	go l.readEvents()

	bpfLog.Info("BPF LSM program loaded and attached to file_open")
	return l, nil
}

// UpdateFilenames replaces the denied_filenames map contents using atomic
// batch operations (BatchUpdate + BatchDelete) when supported (kernel 5.6+).
// Falls back to clear-then-repopulate on ENOSYS.
func (l *BPFLoader) UpdateFilenames(entries []sandbox.BPFDenyEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return fmt.Errorf("loader closed")
	}

	// Build desired state
	desired := make(map[[maxFilename]byte]uint32, len(entries))
	for _, e := range entries {
		desired[filenameKey(e.Key)] = e.RuleID
	}

	if err := updateHashMap(l.maps.DeniedFilenames, desired); err != nil {
		return fmt.Errorf("update denied_filenames: %w", err)
	}

	bpfLog.Debug("Updated denied_filenames: %d entries", len(entries))
	return nil
}

// UpdateInodes replaces the denied_inodes map contents.
// Resolves paths to inodes via stat(2). Uses atomic batch operations when supported.
func (l *BPFLoader) UpdateInodes(entries []sandbox.BPFDenyEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return fmt.Errorf("loader closed")
	}

	// Build desired state (resolve paths to inodes)
	desired := make(map[uint64]uint32, len(entries))
	for _, e := range entries {
		ino, err := resolveInode(e.Key)
		if err != nil {
			bpfLog.Debug("Skip inode for %s: %v", e.Key, err)
			continue
		}
		desired[ino] = e.RuleID
	}

	if err := updateHashMap(l.maps.DeniedInodes, desired); err != nil {
		return fmt.Errorf("update denied_inodes: %w", err)
	}

	bpfLog.Debug("Updated denied_inodes: %d entries", len(entries))
	return nil
}

// UpdateExceptions replaces the allowed_filenames map contents.
// Uses atomic batch operations when supported.
func (l *BPFLoader) UpdateExceptions(filenames []string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return fmt.Errorf("loader closed")
	}

	// Build desired state
	desired := make(map[[maxFilename]byte]uint8, len(filenames))
	for _, name := range filenames {
		desired[filenameKey(name)] = 1
	}

	if err := updateHashMap(l.maps.AllowedFilenames, desired); err != nil {
		return fmt.Errorf("update allowed_filenames: %w", err)
	}

	bpfLog.Debug("Updated allowed_filenames: %d entries", len(filenames))
	return nil
}

// AddTargetPID adds a PID to the enforcement target set.
func (l *BPFLoader) AddTargetPID(pid uint32) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return fmt.Errorf("loader closed")
	}

	var val uint8 = 1
	if err := l.maps.TargetPids.Put(pid, val); err != nil {
		return fmt.Errorf("add target PID %d: %w", pid, err)
	}
	bpfLog.Debug("Added target PID: %d", pid)
	return nil
}

// RemoveTargetPID removes a PID from the enforcement target set.
func (l *BPFLoader) RemoveTargetPID(pid uint32) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return fmt.Errorf("loader closed")
	}

	if err := l.maps.TargetPids.Delete(pid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("remove target PID %d: %w", pid, err)
	}
	bpfLog.Debug("Removed target PID: %d", pid)
	return nil
}

// OnViolation registers a callback for BPF violation events.
func (l *BPFLoader) OnViolation(fn func(sandbox.BPFViolation)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.onViolation = fn
}

// Close detaches the BPF program and releases all resources.
func (l *BPFLoader) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil
	}
	l.closed = true
	close(l.stopCh)

	l.reader.Close()
	l.lsmLnk.Close()

	return nil
}

// readEvents reads violation events from the ring buffer.
func (l *BPFLoader) readEvents() {
	for {
		select {
		case <-l.stopCh:
			return
		default:
		}

		record, err := l.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			bpfLog.Debug("Read ringbuf: %v", err)
			continue
		}

		if len(record.RawSample) < 8 {
			continue
		}

		var evt denyEvent
		evt.PID = binary.LittleEndian.Uint32(record.RawSample[0:4])
		evt.RuleID = binary.LittleEndian.Uint32(record.RawSample[4:8])
		if len(record.RawSample) >= 16 {
			evt.Ino = binary.LittleEndian.Uint64(record.RawSample[8:16])
		}
		if len(record.RawSample) > 16 {
			copy(evt.Filename[:], record.RawSample[16:])
		}

		violation := sandbox.BPFViolation{
			RuleID:    evt.RuleID,
			Filename:  cStringToGo(evt.Filename[:]),
			PID:       evt.PID,
			Inode:     evt.Ino,
			Timestamp: time.Now().Unix(),
		}

		l.mu.Lock()
		cb := l.onViolation
		l.mu.Unlock()

		if cb != nil {
			cb(violation)
		}
	}
}

// filenameKey pads a filename to MAX_FILENAME bytes for BPF hash map key.
func filenameKey(name string) [maxFilename]byte {
	var key [maxFilename]byte
	copy(key[:], name)
	return key
}

// resolveInode returns the inode number for the given path.
func resolveInode(path string) (uint64, error) {
	expanded := sandbox.ExpandHomeDir(path)
	fi, err := os.Stat(expanded)
	if err != nil {
		return 0, err
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("not a syscall.Stat_t")
	}
	return stat.Ino, nil
}

// updateHashMap atomically transitions a BPF hash map to the desired state using
// diff-based batch operations (BatchUpdate + BatchDelete). This avoids a window
// where the map is empty and enforcement is bypassed.
//
// Falls back to clear-then-repopulate when batch ops return ENOSYS (kernel < 5.6).
func updateHashMap[K comparable, V any](m *ebpf.Map, desired map[K]V) error {
	// 1. Read current keys using typed iteration
	current := make(map[K]bool)
	var curKey K
	var curVal V
	iter := m.Iterate()
	for iter.Next(&curKey, &curVal) {
		current[curKey] = true
	}

	// 2. Compute diff: keys to remove = current - desired
	var toRemove []K
	for k := range current {
		if _, want := desired[k]; !want {
			toRemove = append(toRemove, k)
		}
	}

	// 3. Try batch update (add new + overwrite existing) — keeps existing entries alive
	if len(desired) > 0 {
		keys := make([]K, 0, len(desired))
		vals := make([]V, 0, len(desired))
		for k, v := range desired {
			keys = append(keys, k)
			vals = append(vals, v)
		}
		_, err := m.BatchUpdate(keys, vals, &ebpf.BatchOptions{
			Flags: uint64(ebpf.UpdateAny),
		})
		if err != nil {
			if errors.Is(err, syscall.ENOSYS) {
				return updateHashMapFallback(m, desired)
			}
			return fmt.Errorf("batch update: %w", err)
		}
	}

	// 4. Delete stale keys
	if len(toRemove) > 0 {
		_, err := m.BatchDelete(toRemove, nil)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			if errors.Is(err, syscall.ENOSYS) {
				for _, k := range toRemove {
					if err := m.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
						return fmt.Errorf("delete key: %w", err)
					}
				}
				return nil
			}
			return fmt.Errorf("batch delete: %w", err)
		}
	}

	return nil
}

// updateHashMapFallback is the legacy path for kernels < 5.6.
// Uses add-then-remove order to minimize the enforcement gap: new entries are
// populated first, then stale entries are removed. This ensures the map is
// never empty during the transition.
func updateHashMapFallback[K comparable, V any](m *ebpf.Map, desired map[K]V) error {
	// 1. Add/update all desired entries first (keeps enforcement active)
	for k, v := range desired {
		if err := m.Put(k, v); err != nil {
			return fmt.Errorf("put: %w", err)
		}
	}

	// 2. Read current keys and remove stale ones
	var keyBuf K
	var valBuf V
	iter := m.Iterate()
	var keysToDelete []K
	for iter.Next(&keyBuf, &valBuf) {
		k := keyBuf
		if _, want := desired[k]; !want {
			keysToDelete = append(keysToDelete, k)
		}
	}
	for _, k := range keysToDelete {
		if err := m.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}

// cStringToGo converts a null-terminated C string to a Go string.
func cStringToGo(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
