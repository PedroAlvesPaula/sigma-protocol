package proto

import (
	"errors"
	"syscall"
)

// isNoSpace informa se err é falta de espaço em disco (ENOSPC).
func isNoSpace(err error) bool {
	return errors.Is(err, syscall.ENOSPC)
}
