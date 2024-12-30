package tlv

import "github.com/ProtocolScience/AstralGo/binary"

func T10A(arr []byte) []byte {
	return binary.NewWriterF(func(w *binary.Writer) {
		w.WriteUInt16(0x10A)
		w.WriteBytesShort(arr)
	})
}
