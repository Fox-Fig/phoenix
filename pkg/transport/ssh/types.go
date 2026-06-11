package ssh

import "encoding/json"

// ChannelMetadata is passed in the extraData payload of an SSH channel request.
// It tells the server what protocol we are proxying and where to send the traffic.
type ChannelMetadata struct {
	Protocol string `json:"protocol"`
	Target   string `json:"target"`
}

// Encode converts the metadata to a JSON byte slice.
func (c *ChannelMetadata) Encode() []byte {
	b, _ := json.Marshal(c)
	return b
}

// DecodeChannelMetadata parses the extraData payload into ChannelMetadata.
func DecodeChannelMetadata(data []byte) (*ChannelMetadata, error) {
	var meta ChannelMetadata
	err := json.Unmarshal(data, &meta)
	return &meta, err
}
