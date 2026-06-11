package utils

import "strings"

func ContainsExpectedTeardownError(errStr string) bool {
	if errStr == "" {
		return false
	}
	return strings.Contains(errStr, "CANCEL") || 
		strings.Contains(errStr, "connection reset") || 
		strings.Contains(errStr, "client disconnected") ||
		strings.Contains(errStr, "EOF") ||
		strings.Contains(errStr, "http2: stream closed") ||
		strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "broken pipe")
}
