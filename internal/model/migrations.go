package model

import (
	"io/fs"
	"path"
	"strconv"
	"strings"
)

// MaxMigrationVersion returns the highest schema version shipped in this
// binary's embedded migrations. Guards that compare a live database against
// "what this binary supports" must use this instead of a hand-maintained
// constant, which silently goes stale the moment a migration is added.
func MaxMigrationVersion() int64 {
	entries, _ := fs.Glob(embedMigrations, "migrations/*.sql")
	var maxVersion int64
	for _, name := range entries {
		base := path.Base(name)
		idx := strings.IndexByte(base, '_')
		if idx <= 0 {
			continue
		}
		v, err := strconv.ParseInt(base[:idx], 10, 64)
		if err != nil {
			continue
		}
		if v > maxVersion {
			maxVersion = v
		}
	}
	return maxVersion
}
