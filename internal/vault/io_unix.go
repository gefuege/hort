//go:build !windows

package vault

import "os"

func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func replaceFile(from, to string) error {
	return os.Rename(from, to)
}
