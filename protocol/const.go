package protocol

const (
	ALPN        = "passerelle/1"
	ProtocolMin = 1
	ProtocolMax = 1

	MaxControlMessage = 64 << 10
	MaxPreamble       = 4 << 10
	MaxHeaderBytes    = 1 << 20
)

const (
	H2ControlPath = "/v1/control"
	H2DataPath    = "/v1/data"
)

const (
	URIScheme = "passerelle"
)

func DeviceURI(userID, clientID string) string {
	return "passerelle://user/" + userID + "/device/" + clientID
}
