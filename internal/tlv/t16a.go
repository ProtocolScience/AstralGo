package tlv

import "github.com/ProtocolScience/AstralGo/binary"

func T16A(arr []byte) []byte {
	return binary.NewWriterF(func(w *binary.Writer) {
		w.WriteUInt16(0x16A)
		w.WriteBytesShort(arr)
	})
}
