package tlv

import "github.com/ProtocolScience/AstralGo/binary"

func T108(ksid []byte) []byte {
	return binary.NewWriterF(func(w *binary.Writer) {
		w.WriteUInt16(0x108)
		w.WriteBytesShort(ksid)
	})
}
