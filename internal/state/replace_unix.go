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
