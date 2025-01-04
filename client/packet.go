package client

import (
	"encoding/hex"
	"github.com/ProtocolScience/AstralGo/client/internal/network"
	"github.com/ProtocolScience/AstralGo/client/internal/oicq"
	log "github.com/sirupsen/logrus"
)

//go:noinline
func (c *QQClient) buildOicqRequestPacket(uin int64, command uint16, body *oicq.TLV) []byte {
	req := oicq.Message{
		Uin:              uint32(uin),
		Command:          command,
		EncryptionMethod: oicq.EM_ECDH,
		Body:             body.Marshal(),
	}
	return c.oicq.Marshal(&req)
}

//go:noinline
func (c *QQClient) uniPacket(command string, body []byte) (uint16, []byte) {
	seq := c.nextSeq()
	req := network.Request{
		Type:        network.RequestTypeSimple,
		EncryptType: network.EncryptTypeD2Key,
		Uin:         c.Uin,
		SequenceID:  int32(seq),
		CommandName: command,
		Body:        body,
	}
	log.Debugf("uniPacket: %s, %s", command, hex.EncodeToString(body))
	return seq, c.transport.PackPacket(&req)
}

//go:noinline
func (c *QQClient) uniPacketWithSeq(seq uint16, command string, body []byte) []byte {
	req := network.Request{
		Type:        network.RequestTypeSimple,
		EncryptType: network.EncryptTypeD2Key,
		Uin:         c.Uin,
		SequenceID:  int32(seq),
		CommandName: command,
		Body:        body,
	}
	return c.transport.PackPacket(&req)
}
