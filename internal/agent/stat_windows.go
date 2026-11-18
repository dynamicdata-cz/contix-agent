//go:build windows

package agent

import "os"

func fileGID(os.FileInfo) int { return -1 }

func fileUID(os.FileInfo) int { return -1 }
