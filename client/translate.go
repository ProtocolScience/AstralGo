package client

import (
	"github.com/pkg/errors"

	"github.com/ProtocolScience/AstralGo/client/internal/network"
	"github.com/ProtocolScience/AstralGo/client/pb/oidb"
)

func (c *QQClient) buildTranslatePacket(src, dst, text string) (uint16, []byte) {
	body := &oidb.TranslateReqBody{
		BatchTranslateReq: &oidb.BatchTranslateReq{
			SrcLanguage: src,
			DstLanguage: dst,
			SrcTextList: []string{text},
		},
	}
	payload := c.packOIDBPackageProto(2448, 2, body)
	return c.uniPacket("OidbSvc.0x990", payload)
}

func (c *QQClient) Translate(src, dst, text string) (string, error) {
	rsp, err := c.sendAndWait(c.buildTranslatePacket(src, dst, text))
	if err != nil {
		return "", err
	}
	if data, ok := rsp.(*oidb.BatchTranslateRsp); ok {
		if data.ErrorCode != 0 {
			return "", errors.New(string(data.ErrorMsg))
		}
		return data.DstTextList[0], nil
	}
	return "", errors.New("decode error")
}

// OidbSvc.0x990
func decodeTranslateResponse(_ *QQClient, pkt *network.Packet) (any, error) {
	rsp := oidb.TranslateRspBody{}
	err := unpackOIDBPackage(pkt.Payload, &rsp)
	if err != nil {
		return nil, err
	}
	return rsp.BatchTranslateRsp, nil
}
