package http1

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"phoenix/pkg/protocol"
)

// DownlinkMessage represents a chunk of data for a specific virtual stream.
type DownlinkMessage struct {
	StreamID string
	Data     []byte
}

// EncodeDownlink encodes multiple messages into a single binary payload.
func EncodeDownlink(msgs []DownlinkMessage) []byte {
	var buf bytes.Buffer
	for _, msg := range msgs {
		idLen := uint8(len(msg.StreamID))
		buf.WriteByte(idLen)
		buf.WriteString(msg.StreamID)

		dataLen := uint32(len(msg.Data))
		binary.Write(&buf, binary.BigEndian, dataLen)
		buf.Write(msg.Data)
	}
	return buf.Bytes()
}

// DecodeDownlink decodes a binary payload into multiple messages.
func DecodeDownlink(data []byte) ([]DownlinkMessage, error) {
	var msgs []DownlinkMessage
	reader := bytes.NewReader(data)

	for reader.Len() > 0 {
		idLen, err := reader.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		idBuf := make([]byte, idLen)
		if _, err := io.ReadFull(reader, idBuf); err != nil {
			return nil, err
		}

		var dataLen uint32
		if err := binary.Read(reader, binary.BigEndian, &dataLen); err != nil {
			return nil, err
		}

		// Prevent memory exhaustion attacks on huge packets
		if dataLen > 10*1024*1024 {
			return nil, errors.New("chunk too large")
		}

		dataBuf := make([]byte, dataLen)
		if _, err := io.ReadFull(reader, dataBuf); err != nil {
			return nil, err
		}

		msgs = append(msgs, DownlinkMessage{
			StreamID: string(idBuf),
			Data:     dataBuf,
		})
	}

	return msgs, nil
}

// VirtualStream implements io.ReadWriteCloser for an HTTP/1 multiplexed stream.
type VirtualStream struct {
	ID        string
	Protocol  protocol.ProtocolType // The inner protocol (e.g. SOCKS5, SSH)
	Target    string                // Target address
	readBuf   *bytes.Buffer
	readCond  *sync.Cond
	closed    bool
	writeFunc func(data []byte) (int, error)
	closeFunc func() error
}

// NewVirtualStream creates a new in-memory piped stream.
func NewVirtualStream(id string, proto protocol.ProtocolType, target string, writeFunc func([]byte) (int, error), closeFunc func() error) *VirtualStream {
	return &VirtualStream{
		ID:        id,
		Protocol:  proto,
		Target:    target,
		readBuf:   new(bytes.Buffer),
		readCond:  sync.NewCond(&sync.Mutex{}),
		writeFunc: writeFunc,
		closeFunc: closeFunc,
	}
}

// PushData is called by the downlink receiver when new data arrives.
func (v *VirtualStream) PushData(data []byte) {
	v.readCond.L.Lock()
	defer v.readCond.L.Unlock()
	if v.closed {
		return
	}
	v.readBuf.Write(data)
	v.readCond.Signal()
}

// Read implements io.Reader.
func (v *VirtualStream) Read(p []byte) (int, error) {
	v.readCond.L.Lock()
	defer v.readCond.L.Unlock()

	for v.readBuf.Len() == 0 && !v.closed {
		v.readCond.Wait()
	}

	if v.readBuf.Len() > 0 {
		return v.readBuf.Read(p)
	}

	if v.closed {
		return 0, io.EOF
	}

	return 0, io.ErrUnexpectedEOF
}

// Write implements io.Writer.
func (v *VirtualStream) Write(p []byte) (int, error) {
	// If stream is closed locally or remotely, don't write.
	v.readCond.L.Lock()
	closed := v.closed
	v.readCond.L.Unlock()
	
	if closed {
		return 0, io.ErrClosedPipe
	}
	
	if v.writeFunc != nil {
		return v.writeFunc(p)
	}
	return 0, errors.New("write not implemented")
}

// Close implements io.Closer.
func (v *VirtualStream) Close() error {
	v.readCond.L.Lock()
	if v.closed {
		v.readCond.L.Unlock()
		return nil
	}
	v.closed = true
	v.readCond.Broadcast() // wake up readers
	v.readCond.L.Unlock()

	if v.closeFunc != nil {
		return v.closeFunc()
	}
	return nil
}

// MarkClosed only marks the stream as closed, useful for when the server closes it.
func (v *VirtualStream) MarkClosed() {
	v.readCond.L.Lock()
	v.closed = true
	v.readCond.Broadcast()
	v.readCond.L.Unlock()
}
