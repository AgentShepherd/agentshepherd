package rules

import (
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Watcher watches the rules directory for changes and triggers hot reload
type Watcher struct {
	engine   *Engine
	watcher  *fsnotify.Watcher
	stopChan chan struct{}
	wg       sync.WaitGroup

	// Debounce rapid file changes
	debounce     time.Duration
	lastReload   time.Time
	pendingTimer *time.Timer
	timerMu      sync.Mutex
}

// NewWatcher creates a new file watcher
func NewWatcher(engine *Engine) (*Watcher, error) {
	fsWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	w := &Watcher{
		engine:   engine,
		watcher:  fsWatcher,
		stopChan: make(chan struct{}),
		debounce: 500 * time.Millisecond,
	}

	return w, nil
}

// Start begins watching the rules directory
func (w *Watcher) Start() error {
	rulesDir := w.engine.GetLoader().GetUserDir()
	if rulesDir == "" {
		log.Warn("No user rules directory configured, watcher not started")
		return nil
	}

	// Add the directory to watch
	if err := w.watcher.Add(rulesDir); err != nil {
		// Directory might not exist yet
		log.Warn("Cannot watch rules directory (may not exist yet): %v", err)
		return nil
	}

	w.wg.Add(1)
	go w.run()

	log.Info("Watching rules directory: %s", rulesDir)
	return nil
}

// Stop stops the watcher
func (w *Watcher) Stop() error {
	close(w.stopChan)
	w.wg.Wait()

	w.timerMu.Lock()
	if w.pendingTimer != nil {
		w.pendingTimer.Stop()
	}
	w.timerMu.Unlock()

	return w.watcher.Close()
}

func (w *Watcher) run() {
	defer w.wg.Done()

	for {
		select {
		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}
			w.handleEvent(event)

		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			log.Warn("Watcher error: %v", err)

		case <-w.stopChan:
			return
		}
	}
}

func (w *Watcher) handleEvent(event fsnotify.Event) {
	// Only care about YAML files
	if !strings.HasSuffix(event.Name, ".yaml") {
		return
	}

	// Only care about write, create, remove, rename
	if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) == 0 {
		return
	}

	log.Debug("Rule file changed: %s (%s)", filepath.Base(event.Name), event.Op)

	// Debounce: schedule reload after debounce period
	w.scheduleReload()
}

func (w *Watcher) scheduleReload() {
	w.timerMu.Lock()
	defer w.timerMu.Unlock()

	// Cancel any pending reload
	if w.pendingTimer != nil {
		w.pendingTimer.Stop()
	}

	// Schedule new reload
	w.pendingTimer = time.AfterFunc(w.debounce, func() {
		w.doReload()
	})
}

func (w *Watcher) doReload() {
	w.timerMu.Lock()
	w.lastReload = time.Now()
	w.timerMu.Unlock()

	log.Info("Hot reloading user rules...")
	if err := w.engine.ReloadUserRules(); err != nil {
		log.Error("Failed to reload rules: %v", err)
	}
}
