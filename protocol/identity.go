package protocol

import (
	"fmt"
	"strings"
)

func ParseDeviceURI(uri string) (userID, clientID string, err error) {
	const prefix = "passerelle://user/"
	if !strings.HasPrefix(uri, prefix) {
		return "", "", fmt.Errorf("unsupported identity uri")
	}
	rest := strings.TrimPrefix(uri, prefix)
	user, device, ok := strings.Cut(rest, "/device/")
	if !ok || user == "" || device == "" || strings.Contains(user, "/") {
		return "", "", fmt.Errorf("malformed identity uri")
	}
	return user, device, nil
}
