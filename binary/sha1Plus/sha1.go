package sha1Plus

import (
	"encoding/binary"
)

const (
	SHA1_BLOCK_SIZE  = 64
	SHA1_DIGEST_SIZE = 20
)

type Sha1Plus struct {
	state  [5]uint32
	count  [2]uint32
	buffer [SHA1_BLOCK_SIZE]byte
}

var PADDING = []byte{
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

func NewSha1Plus() *Sha1Plus {
	s := &Sha1Plus{}
	s.Reset()
	return s
}

func (s *Sha1Plus) Reset() {
	s.state[0] = 0x67452301
	s.state[1] = 0xEFCDAB89
	s.state[2] = 0x98BADCFE
	s.state[3] = 0x10325476
	s.state[4] = 0xC3D2E1F0
	s.count[0] = 0
	s.count[1] = 0
}
func (s *Sha1Plus) NonFinal() []byte {
	var digest = make([]byte, 20)
	for i := 0; i < 5; i++ {
		binary.LittleEndian.PutUint32(digest[i*4:], s.state[i])
	}
	return digest
}

func (s *Sha1Plus) transform(data []byte) {
	var w [80]uint32
	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(data[i*4 : i*4+4])
	}

	for i := 16; i < 80; i++ {
		w[i] = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]
		w[i] = (w[i] << 1) | (w[i] >> 31)
	}

	a, b, c, d, e := s.state[0], s.state[1], s.state[2], s.state[3], s.state[4]

	for i := 0; i < 80; i++ {
		var f, k uint32
		switch {
		case i < 20:
			f = (b & c) | (^b & d)
			k = 0x5A827999
		case i < 40:
			f = b ^ c ^ d
			k = 0x6ED9EBA1
		case i < 60:
			f = (b & c) | (b & d) | (c & d)
			k = 0x8F1BBCDC
		default:
			f = b ^ c ^ d
			k = 0xCA62C1D6
		}

		temp := ((a << 5) | (a >> 27)) + f + e + w[i] + k
		e = d
		d = c
		c = (b << 30) | (b >> 2)
		b = a
		a = temp
	}

	s.state[0] += a
	s.state[1] += b
	s.state[2] += c
	s.state[3] += d
	s.state[4] += e
}

func (s *Sha1Plus) Update(data []byte) {
	index := (s.count[0] >> 3) & 0x3F
	s.count[0] += uint32(len(data)) << 3
	if s.count[0] < uint32(len(data))<<3 {
		s.count[1]++
	}
	s.count[1] += uint32(len(data)) >> 29

	partLen := SHA1_BLOCK_SIZE - index
	var i int
	if len(data) >= int(partLen) {
		copy(s.buffer[index:], data[:partLen])
		s.transform(s.buffer[:])

		for i = int(partLen); i+SHA1_BLOCK_SIZE <= len(data); i += SHA1_BLOCK_SIZE {
			s.transform(data[i : i+SHA1_BLOCK_SIZE])
		}
		index = 0
	} else {
		i = 0
	}

	copy(s.buffer[index:], data[i:])
}

func (s *Sha1Plus) Final() []byte {
	var digest = make([]byte, 20)
	if len(digest) != SHA1_DIGEST_SIZE {
		panic("Digest array must be of size SHA1_DIGEST_SIZE")
	}

	bits := make([]byte, 8)
	binary.BigEndian.PutUint32(bits[0:], s.count[1])
	binary.BigEndian.PutUint32(bits[4:], s.count[0])

	index := (s.count[0] >> 3) & 0x3f
	padLen := 56 - index
	if index >= 56 {
		padLen += SHA1_BLOCK_SIZE
	}

	s.Update(PADDING[:padLen])
	s.Update(bits)

	for i := 0; i < 5; i++ {
		binary.BigEndian.PutUint32(digest[i*4:], s.state[i])
	}
	return digest
}
