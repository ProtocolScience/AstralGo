package highway

import (
	"bytes"
	"encoding/binary"
	"net"
)

// frame 包格式
//
//   - STX: 0x28(40)
//   - head length
//   - body length
//   - head data
//   - body data
//   - ETX: 0x29(41)
//
// 节省内存, 可被go runtime优化为writev操作
func frame(head []byte, body []byte) net.Buffers {
	var buf bytes.Buffer
	buf.WriteByte(40)
	_ = binary.Write(&buf, binary.BigEndian, int32(len(head)))
	_ = binary.Write(&buf, binary.BigEndian, int32(len(body)))
	buf.Write(head)
	buf.Write(body)
	buf.WriteByte(41)
	return net.Buffers{buf.Bytes()}
}
