package oicq

import (
	"crypto/rand"
	goBinary "encoding/binary"

	"github.com/pkg/errors"

	"github.com/ProtocolScience/AstralGo/binary"
)

type Codec struct {
	ecdh      *session
	randomKey []byte

	WtSessionTicketKey []byte
}

func NewCodec(uin int64) *Codec {
	c := &Codec{
		ecdh:      newSession(),
		randomKey: make([]byte, 16),
	}
	rand.Read(c.randomKey)
	c.ecdh.fetchPubKey(uin)
	return c
}

type EncryptionMethod byte

const (
	EM_ECDH EncryptionMethod = iota
	EM_ST
)

type Message struct {
	Uin              uint32
	Command          uint16
	EncryptionMethod EncryptionMethod
	Body             []byte
}

func (c *Codec) Marshal(m *Message) []byte {
	w := binary.SelectWriter()
	defer binary.PutWriter(w)

	w.WriteByte(0x02)
	w.WriteUInt16(0)    // len 占位
	w.WriteUInt16(8001) // version?
	w.WriteUInt16(m.Command)
	w.WriteUInt16(1)
	w.WriteUInt32(m.Uin)
	w.WriteByte(0x03)
	switch m.EncryptionMethod {
	case EM_ECDH:
		w.WriteByte(0x87)
	case EM_ST:
		w.WriteByte(0x45)
	}
	w.WriteByte(0)
	w.WriteUInt32(2)
	w.WriteUInt32(0)
	w.WriteUInt32(0)

	switch m.EncryptionMethod {
	case EM_ECDH:
		w.WriteByte(0x02)
		w.WriteByte(0x01)
		w.Write(c.randomKey)
		w.WriteUInt16(0x01_31)
		w.WriteUInt16(c.ecdh.SvrPublicKeyVer)
		w.WriteUInt16(uint16(len(c.ecdh.PublicKey)))
		w.Write(c.ecdh.PublicKey)
		w.EncryptAndWrite(c.ecdh.ShareKey, m.Body)

	case EM_ST:
		w.WriteByte(0x01)
		w.WriteByte(0x03)
		w.Write(c.randomKey)
		w.WriteUInt16(0x0102)
		w.WriteUInt16(0x0000)
		w.EncryptAndWrite(c.randomKey, m.Body)
	}
	w.WriteByte(0x03)

	buf := make([]byte, len(w.Bytes()))
	copy(buf, w.Bytes())
	goBinary.BigEndian.PutUint16(buf[1:3], uint16(len(buf)))
	return buf
}

var (
	ErrEmptyData          = errors.New("unknown empty data")
	ErrUnknownFlag        = errors.New("unknown flag")
	ErrUnknownEncryptType = errors.New("unknown encrypt type")
)

func (c *Codec) Unmarshal(data []byte) (*Message, error) {
	if len(data) == 0 {
		return nil, ErrEmptyData
	}
	reader := binary.NewReader(data)
	flag := reader.ReadByte()
	if flag != 0x2 {
		return nil, ErrUnknownFlag
	}
	m := new(Message)
	reader.ReadUInt16() // len
	reader.ReadUInt16() // version?
	m.Command = reader.ReadUInt16()
	reader.ReadUInt16() // 1?
	m.Uin = uint32(reader.ReadInt32())
	reader.ReadByte()
	encryptType := reader.ReadByte()
	reader.ReadByte()
	switch encryptType {
	case 0:
		d := reader.ReadBytes(reader.Len() - 1)
		defer func() {
			if pan := recover(); pan != nil {
				m.Body = binary.NewTeaCipher(c.randomKey).Decrypt(d)
			}
		}()
		m.Body = binary.NewTeaCipher(c.ecdh.ShareKey).Decrypt(d)
	case 3:
		d := reader.ReadBytes(reader.Len() - 1)
		m.Body = binary.NewTeaCipher(c.WtSessionTicketKey).Decrypt(d)
	default:
		return nil, ErrUnknownEncryptType
	}
	return m, nil
}

type TLV struct {
	Command uint16
	List    [][]byte
}

func (t *TLV) Marshal() []byte {
	w := binary.SelectWriter()
	defer binary.PutWriter(w)

	w.WriteUInt16(t.Command)
	w.WriteUInt16(uint16(len(t.List)))
	for _, elem := range t.List {
		w.Write(elem)
	}

	return append([]byte(nil), w.Bytes()...)
}

func (t *TLV) Append(b ...[]byte) {
	t.List = append(t.List, b...)
}
