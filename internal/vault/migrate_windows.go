//go:build windows

package vault

// Windows does not expose directory fsync through os.File. Atomic replacement
// uses the existing platform rename path after the backup file is flushed.
func syncMigrationDir(path string) error { return nil }
