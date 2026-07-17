package lsec

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type eventLog struct {
	path string
}

type eventLogRow struct {
	Kind      string          `json:"kind"`
	JSON      json.RawMessage `json:"json"`
	CreatedAt string          `json:"created_at"`
}

func (l eventLog) append(kind string, body []byte, createdAt time.Time) error {
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := lockFile(f); err != nil {
		return err
	}
	defer unlockFile(f)
	_, err = fmt.Fprintf(f, `{"kind":%q,"json":%s,"created_at":%q}`+"\n", kind, body, createdAt.Format(time.RFC3339Nano))
	return err
}

func (l eventLog) forEach(fn func([]byte) error) error {
	f, err := os.Open(l.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	if err := lockFile(f); err != nil {
		return err
	}
	defer unlockFile(f)

	reader := bufio.NewReader(f)
	for {
		line, readErr := reader.ReadBytes('\n')
		line = bytes.TrimSpace(line)
		if len(line) > 0 {
			if err := fn(line); err != nil {
				return err
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}

func parseEventLogRow(line []byte) (eventLogRow, time.Time, bool) {
	var row eventLogRow
	if err := json.Unmarshal(line, &row); err != nil {
		return eventLogRow{}, time.Time{}, false
	}
	createdAt, _ := time.Parse(time.RFC3339Nano, row.CreatedAt)
	return row, createdAt, true
}
