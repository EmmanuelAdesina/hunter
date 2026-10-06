//go:build !windows

package state

import "os"

// replaceFile atomically moves src onto dst.
//
// os.Rename is atomic on POSIX systems when both paths are on the same
// filesystem, which they are because the temporary file is created in the
// destination directory.
func replaceFile(src, dst string) error {
	return os.Rename(src, dst)
}

// syncDirectory makes renames and removals durable across a host interruption.
func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
