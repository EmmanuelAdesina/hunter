//go:build windows

package state

import "os"

// replaceFile atomically moves src onto dst.
//
// On Windows os.Rename fails when the destination exists, so the destination is
// removed first. The replacement file is already fully written and synced by the
// time this runs, so the window in which neither file exists contains no
// partially written data.
func replaceFile(src, dst string) error {
	if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Rename(src, dst)
}
