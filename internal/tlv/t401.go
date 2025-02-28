package tlv

import "github.com/ProtocolScience/AstralGo/binary"

func T401(d []byte) []byte {
	return binary.NewWriterF(func(w *binary.Writer) {
		w.WriteUInt16(0x401)
		w.WriteBytesShort(d)
	})
}
