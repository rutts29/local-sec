//go:build !unix

package lsec

import "os"

func providerInputLinkRejection(os.FileInfo) string {
	return "link_count_unavailable"
}
