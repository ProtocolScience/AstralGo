package client

import (
	"crypto/md5"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/ProtocolScience/AstralGo/binary"
	"github.com/ProtocolScience/AstralGo/binary/jce"
	"github.com/ProtocolScience/AstralGo/client/internal/auth"
	"github.com/ProtocolScience/AstralGo/client/internal/network"
	"github.com/ProtocolScience/AstralGo/client/internal/tlv"
	"github.com/ProtocolScience/AstralGo/client/pb"
	"github.com/ProtocolScience/AstralGo/client/pb/cmd0x352"
	"github.com/ProtocolScience/AstralGo/client/pb/cmd0x6ff"
	"github.com/ProtocolScience/AstralGo/client/pb/msg"
	"github.com/ProtocolScience/AstralGo/client/pb/oidb"
	"github.com/ProtocolScience/AstralGo/client/pb/profilecard"
	"github.com/ProtocolScience/AstralGo/client/pb/structmsg"
	"github.com/ProtocolScience/AstralGo/internal/proto"
	"github.com/ProtocolScience/AstralGo/utils"
)

var (
	groupJoinLock  sync.Mutex
	groupLeaveLock sync.Mutex
)

// wtlogin.login
func decodeLoginResponse(c *QQClient, pkt *network.Packet) (any, error) {
	reader := binary.NewReader(pkt.Payload)
	reader.ReadUInt16() // sub command
	t := reader.ReadByte()
	reader.ReadUInt16()
	m, err := tlv.NewDecoder(2, 2).DecodeRecordMap(reader.ReadAvailable())
	if err != nil {
		return nil, err
	}
	if m.Exists(0x402) {
		c.sig.Dpwd = []byte(utils.RandomString(16))
		c.sig.T402 = m[0x402]
		h := md5.Sum(append(append(c.Device().Guid, c.sig.Dpwd...), c.sig.T402...))
		c.sig.G = h[:]
	}
	if m.Exists(0x546) {
		c.sig.T547 = auth.CalcPow(m[0x546])
	}
	// c.logger.Info("login response %v", t)
	if t == 0 { // login success
		// if t150, ok := m[0x150]; ok {
		//  	c.t150 = t150
		// }
		// if t161, ok := m[0x161]; ok {
		//  	c.decodeT161(t161)
		// }
		if m.Exists(0x403) {
			c.sig.RandSeed = m[0x403]
		}
		c.decodeT119(m[0x119], c.Device().TgtgtKey)
		return LoginResponse{
			Success: true,
		}, nil
	}
	if t == 2 {
		c.sig.T104 = m[0x104]
		if m.Exists(0x192) {
			return LoginResponse{
				Success:   false,
				Code:      t,
				VerifyUrl: string(m[0x192]),
				Error:     SliderNeededError,
			}, nil
		}
		if m.Exists(0x165) { // image
			imgData := binary.NewReader(m[0x105])
			signLen := imgData.ReadUInt16()
			imgData.ReadUInt16()
			sign := imgData.ReadBytes(int(signLen))
			return LoginResponse{
				Success:      false,
				Code:         t,
				Error:        NeedCaptcha,
				CaptchaImage: imgData.ReadAvailable(),
				CaptchaSign:  sign,
			}, nil
		} else {
			return LoginResponse{
				Success: false,
				Code:    t,
				Error:   UnknownLoginError,
			}, nil
		}
	} // need captcha

	if t == 40 {
		return LoginResponse{
			Success:      false,
			Code:         t,
			ErrorMessage: "账号被冻结",
			Error:        UnknownLoginError,
		}, nil
	}

	if t == 160 || t == 239 {
		if t174, ok := m[0x174]; ok { // 短信验证
			c.sig.T104 = m[0x104]
			c.sig.T174 = t174
			c.sig.RandSeed = m[0x403]
			phone := func() string {
				r := binary.NewReader(m[0x178])
				r.ReadStringShort()
				return r.ReadStringShort()
			}()
			if t204, ok := m[0x204]; ok { // 同时支持扫码验证 ?
				return LoginResponse{
					Success:      false,
					Code:         t,
					Error:        SMSOrVerifyNeededError,
					VerifyUrl:    string(t204),
					SMSPhone:     phone,
					ErrorMessage: string(m[0x17e]),
				}, nil
			}
			return LoginResponse{
				Success:      false,
				Code:         t,
				Error:        SMSNeededError,
				SMSPhone:     phone,
				ErrorMessage: string(m[0x17e]),
			}, nil
		}

		if _, ok := m[0x17b]; ok { // 二次验证
			c.sig.T104 = m[0x104]
			return LoginResponse{
				Success: false,
				Code:    t,
				Error:   SMSNeededError,
			}, nil
		}

		if t204, ok := m[0x204]; ok { // 扫码验证
			return LoginResponse{
				Success:      false,
				Code:         t,
				Error:        UnsafeDeviceError,
				VerifyUrl:    string(t204),
				ErrorMessage: "",
			}, nil
		}
	}

	if t == 162 {
		return LoginResponse{
			Code:  t,
			Error: TooManySMSRequestError,
		}, nil
	}

	if t == 204 {
		c.sig.T104 = m[0x104]
		c.sig.RandSeed = m[0x403]
		return c.sendAndWait(c.buildDeviceLockLoginPacket())
	} // drive lock

	if t149, ok := m[0x149]; ok {
		t149r := binary.NewReader(t149)
		t149r.ReadBytes(2)
		t149r.ReadStringShort() // title
		return LoginResponse{
			Success:      false,
			Code:         t,
			Error:        OtherLoginError,
			ErrorMessage: t149r.ReadStringShort(),
		}, nil
	}

	if t146, ok := m[0x146]; ok {
		t146r := binary.NewReader(t146)
		t146r.ReadBytes(4)      // ver and code
		t146r.ReadStringShort() // title
		return LoginResponse{
			Success:      false,
			Code:         t,
			Error:        OtherLoginError,
			ErrorMessage: t146r.ReadStringShort(),
		}, nil
	}
	c.debug("unknown login response: %v", t)
	for k, v := range m {
		c.debug("Type: %d Value: %x", k, v)
	}
	return nil, errors.Errorf("unknown login response: %v", t) // ?
}

type ServerResponseError struct {
	Code    int
	Message string
}

func (e ServerResponseError) Error() string {
	return e.Message
}

// wtlogin.exchange_emp
func decodeExchangeEmpResponse(c *QQClient, pkt *network.Packet) (any, error) {
	reader := binary.NewReader(pkt.Payload)
	cmd := reader.ReadUInt16()
	t := reader.ReadByte()
	reader.ReadUInt16()

	m, err := tlv.NewDecoder(2, 2).DecodeRecordMap(reader.ReadAvailable())
	if err != nil {
		return nil, &ServerResponseError{
			Code:    1001,
			Message: "error decoding record map",
		}
	}

	if t != 0 {
		return nil, &ServerResponseError{
			Code:    int(t),
			Message: fmt.Sprintf("exchange_emp failed with code: %v", t),
		}
	}

	switch cmd {
	case 15:
		c.decodeT119R(m[0x119])
	case 11:
		h := md5.Sum(c.sig.D2Key)
		c.decodeT119(m[0x119], h[:])
	}

	return nil, nil
}

// wtlogin.trans_emp
func decodeTransEmpResponse(c *QQClient, pkt *network.Packet) (any, error) {
	if len(pkt.Payload) < 48 {
		return nil, errors.New("missing payload length")
	}
	reader := binary.NewReader(pkt.Payload)
	reader.ReadBytes(5) // trans req head
	reader.ReadByte()
	reader.ReadUInt16()
	cmd := reader.ReadUInt16()
	reader.ReadBytes(21)
	reader.ReadByte()
	reader.ReadUInt16()
	reader.ReadUInt16()
	reader.ReadInt32()
	reader.ReadInt64()
	body := binary.NewReader(reader.ReadBytes(reader.Len() - 1))
	if cmd == 0x31 {
		body.ReadUInt16()
		body.ReadInt32()
		code := body.ReadByte()
		if code != 0 {
			return nil, errors.Errorf("wtlogin.trans_emp sub cmd 0x31 error: %v", code)
		}
		sig := body.ReadBytesShort()
		body.ReadUInt16()
		m, err := tlv.NewDecoder(2, 2).DecodeRecordMap(body.ReadAvailable())
		if err != nil {
			return nil, err
		}
		if m.Exists(0x17) {
			return &QRCodeLoginResponse{
				State:     QRCodeImageFetch,
				ImageData: m[0x17],
				Sig:       sig,
			}, nil
		}
		return nil, errors.Errorf("wtlogin.trans_emp sub cmd 0x31 error: image not found")
	}
	if cmd == 0x12 {
		aVarLen := body.ReadUInt16()
		if aVarLen != 0 {
			aVarLen-- // 阴间的位移操作
			if body.ReadByte() == 2 {
				body.ReadInt64() // uin ?
				aVarLen -= 8
			}
		}
		if aVarLen > 0 {
			body.ReadBytes(int(aVarLen))
		}
		body.ReadInt32() // app id?
		code := body.ReadByte()
		if code != 0 {
			if code == 0x30 {
				return &QRCodeLoginResponse{State: QRCodeWaitingForScan}, nil
			}
			if code == 0x35 {
				return &QRCodeLoginResponse{State: QRCodeWaitingForConfirm}, nil
			}
			if code == 0x36 {
				return &QRCodeLoginResponse{State: QRCodeCanceled}, nil
			}
			if code == 0x11 {
				return &QRCodeLoginResponse{State: QRCodeTimeout}, nil
			}
			return nil, errors.Errorf("wtlogin.trans_emp sub cmd 0x12 error: %v", code)
		}
		c.Uin = body.ReadInt64()
		c.highwaySession.Uin = strconv.FormatInt(c.Uin, 10)
		body.ReadInt32() // sig create time
		body.ReadUInt16()
		m, err := tlv.NewDecoder(2, 2).DecodeRecordMap(body.ReadAvailable())
		if err != nil {
			return nil, err
		}
		if !m.Exists(0x18) || !m.Exists(0x1e) || !m.Exists(0x19) {
			return nil, errors.New("wtlogin.trans_emp sub cmd 0x12 error: tlv error")
		}
		c.Device().TgtgtKey = m[0x1e]
		return &QRCodeLoginResponse{State: QRCodeConfirmed, LoginInfo: &QRCodeLoginInfo{
			tmpPwd:      m[0x18],
			tmpNoPicSig: m[0x19],
			tgtQR:       m[0x65],
		}}, nil
	}
	return nil, errors.Errorf("unknown trans_emp response: %v", cmd)
}

// ConfigPushSvc.PushReq
func decodePushReqPacket(c *QQClient, pkt *network.Packet) (any, error) {
	request := &jce.RequestPacket{}
	request.ReadFrom(jce.NewJceReader(pkt.Payload))
	data := &jce.RequestDataVersion2{}
	data.ReadFrom(jce.NewJceReader(request.SBuffer))
	r := jce.NewJceReader(data.Map["PushReq"]["ConfigPush.PushReq"][1:])
	t := r.ReadInt32(1)
	jceBuf := r.ReadBytes(2)
	if len(jceBuf) > 0 {
		switch t {
		case 1:
			ssoPkt := jce.NewJceReader(jceBuf)
			servers := ssoPkt.ReadSsoServerInfos(1)
			if len(servers) > 0 {
				var adds []netip.AddrPort
				for _, s := range servers {
					if strings.Contains(s.Server, "com") {
						continue
					}
					c.debug("got new server addr: %v location: %v", s.Server, s.Location)
					addr, err := netip.ParseAddr(s.Server)
					if err == nil {
						adds = append(adds, netip.AddrPortFrom(addr, uint16(s.Port)))
					}
				}
				f := true
				for _, e := range c.eventHandlers.serverUpdatedHandlers {
					cover(func() {
						if !e(c, &ServerUpdatedEvent{Servers: servers}) {
							f = false
						}
					})
				}
				if f {
					c.SetCustomServer(adds)
				}
				return nil, nil
			}
		case 2:
			fmtPkt := jce.NewJceReader(jceBuf)
			list := &jce.FileStoragePushFSSvcList{}
			list.ReadFrom(fmtPkt)
			c.debug("got file storage svc push.")
			// c.fileStorageInfo = list
			rsp := cmd0x6ff.C501RspBody{}
			if err := proto.Unmarshal(list.BigDataChannel.PbBuf, &rsp); err == nil && rsp.RspBody != nil {
				c.highwaySession.SigSession = rsp.RspBody.SigSession
				c.highwaySession.SessionKey = rsp.RspBody.SessionKey
				for _, srv := range rsp.RspBody.Addrs {
					if srv.ServiceType.Unwrap() == 10 {
						for _, addr := range srv.Addrs {
							c.highwaySession.AppendAddr(addr.Ip.Unwrap(), addr.Port.Unwrap())
						}
					}
					/*
						if srv.ServiceType.Unwrap() == 21 {
							for _, addr := range srv.Addrs {
								c.otherSrvAddrs = append(c.otherSrvAddrs, fmt.Sprintf("%v:%v", binary.UInt32ToIPV4Address(addr.Ip.Unwrap()), addr.Port.Unwrap()))
							}
						}

					*/
				}
			}
		}
	}

	seq := r.ReadInt64(3)
	_, resp := c.buildConfPushRespPacket(t, seq, jceBuf)
	return nil, c.sendPacket(resp)
}

// MessageSvc.PbGetMsg
func decodeMessageSvcPacket(c *QQClient, pkt *network.Packet) (any, error) {
	rsp := msg.GetMessageResponse{}
	err := proto.Unmarshal(pkt.Payload, &rsp)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal protobuf message")
	}
	c.c2cMessageSyncProcessor(&rsp, pkt.Params)
	return nil, nil
}

// MessageSvc.PushNotify
func decodeSvcNotify(c *QQClient, pkt *network.Packet) (any, error) {
	request := &jce.RequestPacket{}
	request.ReadFrom(jce.NewJceReader(pkt.Payload[4:]))
	data := &jce.RequestDataVersion2{}
	data.ReadFrom(jce.NewJceReader(request.SBuffer))
	if len(data.Map) == 0 {
		_, err := c.sendAndWait(c.buildGetMessageRequestPacket(msg.SyncFlag_START, time.Now().Unix()))
		return nil, err
	}
	notify := &jce.RequestPushNotify{}
	notify.ReadFrom(jce.NewJceReader(data.Map["req_PushNotify"]["PushNotifyPack.RequestPushNotify"][1:]))
	if decoder, typ := peekC2CDecoder(notify.MsgType); decoder != nil {
		// notify.MsgType != 85 && notify.MsgType != 36 moves to _c2c_decoders.go [nonSvcNotifyTroopSystemMsgDecoders]
		if typ == troopSystemMsgDecoders {
			c.exceptAndDispatchGroupSysMsg()
			return nil, nil
		}
		if typ == sysMsgDecoders {
			_, pkt := c.buildSystemMsgNewFriendPacket()
			return nil, c.sendPacket(pkt)
		}
	}
	_, err := c.sendAndWait(c.buildGetMessageRequestPacket(msg.SyncFlag_START, time.Now().Unix()))
	return nil, err
}

// SummaryCard.ReqSummaryCard
func decodeSummaryCardResponse(_ *QQClient, pkt *network.Packet) (any, error) {
	request := &jce.RequestPacket{}
	request.ReadFrom(jce.NewJceReader(pkt.Payload))
	data := &jce.RequestDataVersion2{}
	data.ReadFrom(jce.NewJceReader(request.SBuffer))
	rsp := func() *jce.JceReader {
		if r, ok := data.Map["RespSummaryCard"]["SummaryCard.RespSummaryCard"]; ok {
			return jce.NewJceReader(r[1:])
		}
		return jce.NewJceReader(data.Map["RespSummaryCard"]["SummaryCard_Old.RespSummaryCard"][1:])
	}()
	info := &SummaryCardInfo{
		Sex:      rsp.ReadByte(1),
		Age:      rsp.ReadByte(2),
		Nickname: rsp.ReadString(3),
		Level:    rsp.ReadInt32(5),
		City:     rsp.ReadString(7),
		Sign:     rsp.ReadString(8),
		Mobile:   rsp.ReadString(11),
		Uin:      rsp.ReadInt64(23),
	}
	vipInfo := rsp.ReadMapIntVipInfo(29) // 1 -> vip, 3 -> svip
	if v1, v3 := vipInfo[1], vipInfo[3]; v1 != nil || v3 != nil {
		if v1.Open != 0 {
			info.VipLevel = fmt.Sprintf("vip%d", v1.Level)
		}
		if v3.Open != 0 {
			info.VipLevel = fmt.Sprintf("svip%d", v3.Level)
		}
	}

	richSign := rsp.ReadBytes(32)
	records, _ := tlv.NewDecoder(1, 1).Decode(richSign)
	for _, r := range records {
		if r.Tag == 3 {
			info.Sign = string(r.Value)
		}
	}

	info.LoginDays = rsp.ReadInt64(36)
	services := rsp.ReadByteArrArr(46)
	readService := func(buf []byte) (*profilecard.BusiComm, []byte) {
		r := binary.NewReader(buf)
		r.ReadByte()
		l1 := r.ReadInt32()
		l2 := r.ReadInt32()
		comm := r.ReadBytes(int(l1))
		d := r.ReadBytes(int(l2))
		c := &profilecard.BusiComm{}
		_ = proto.Unmarshal(comm, c)
		return c, d
	}
	for _, buf := range services {
		comm, payload := readService(buf)
		if comm.Service.Unwrap() == 16 {
			rsp := profilecard.GateVaProfileGateRsp{}
			_ = proto.Unmarshal(payload, &rsp)
			if rsp.QidInfo != nil {
				info.Qid = rsp.QidInfo.Qid.Unwrap()
			}
		}
	}
	return info, nil
}

// friendlist.getFriendGroupList
func decodeFriendGroupListResponse(_ *QQClient, pkt *network.Packet) (any, error) {
	request := &jce.RequestPacket{}
	request.ReadFrom(jce.NewJceReader(pkt.Payload))
	data := &jce.RequestDataVersion3{}
	data.ReadFrom(jce.NewJceReader(request.SBuffer))
	r := jce.NewJceReader(data.Map["FLRESP"][1:])
	totalFriendCount := r.ReadInt16(5)
	friends := r.ReadFriendInfos(7)
	l := make([]*FriendInfo, 0, len(friends))
	for _, f := range friends {
		l = append(l, &FriendInfo{
			Uin:      f.FriendUin,
			Nickname: f.Nick,
			Remark:   f.Remark,
			FaceId:   f.FaceId,
		})
	}
	rsp := &FriendListResponse{
		TotalCount: int32(totalFriendCount),
		List:       l,
	}
	return rsp, nil
}

// friendlist.delFriend
func decodeFriendDeleteResponse(_ *QQClient, pkt *network.Packet) (any, error) {
	request := &jce.RequestPacket{}
	request.ReadFrom(jce.NewJceReader(pkt.Payload))
	data := &jce.RequestDataVersion3{}
	data.ReadFrom(jce.NewJceReader(request.SBuffer))
	r := jce.NewJceReader(data.Map["DFRESP"][1:])
	if ret := r.ReadInt32(2); ret != 0 {
		return nil, errors.Errorf("delete friend error: %v", ret)
	}
	return nil, nil
}

// friendlist.GetTroopListReqV2
func decodeGroupListResponse(c *QQClient, pkt *network.Packet) (any, error) {
	request := &jce.RequestPacket{}
	request.ReadFrom(jce.NewJceReader(pkt.Payload))
	data := &jce.RequestDataVersion3{}
	data.ReadFrom(jce.NewJceReader(request.SBuffer))
	r := jce.NewJceReader(data.Map["GetTroopListRespV2"][1:])
	vecCookie := r.ReadBytes(4)
	groups := r.ReadTroopNumbers(5)
	l := make([]*GroupInfo, 0, len(groups))
	for _, g := range groups {
		l = append(l, &GroupInfo{
			Uin:            g.GroupUin,
			Code:           g.GroupCode,
			Name:           g.GroupName,
			OwnerUin:       g.GroupOwnerUin,
			MemberCount:    uint16(g.MemberNum),
			MaxMemberCount: uint16(g.MaxGroupMemberNum),
			client:         c,
		})
	}
	if len(vecCookie) > 0 {
		rsp, err := c.sendAndWait(c.buildGroupListRequestPacket(vecCookie))
		if err != nil {
			return nil, err
		}
		l = append(l, rsp.([]*GroupInfo)...)
	}
	return l, nil
}

// friendlist.GetTroopMemberListReq
func decodeGroupMemberListResponse(_ *QQClient, pkt *network.Packet) (any, error) {
	request := &jce.RequestPacket{}
	request.ReadFrom(jce.NewJceReader(pkt.Payload))
	data := &jce.RequestDataVersion3{}
	data.ReadFrom(jce.NewJceReader(request.SBuffer))
	r := jce.NewJceReader(data.Map["GTMLRESP"][1:])
	members := r.ReadTroopMemberInfos(3)
	next := r.ReadInt64(4)
	l := make([]*GroupMemberInfo, 0, len(members))
	for _, m := range members {
		permission := Member
		if m.Flag&1 != 0 {
			permission = Administrator
		}
		l = append(l, &GroupMemberInfo{
			Uin:             m.MemberUin,
			Nickname:        m.Nick,
			Gender:          m.Gender,
			CardName:        m.Name,
			Level:           uint16(m.MemberLevel),
			JoinTime:        m.JoinTime,
			LastSpeakTime:   m.LastSpeakTime,
			SpecialTitle:    m.SpecialTitle,
			ShutUpTimestamp: m.ShutUpTimestap,
			Permission:      permission,
		})
	}
	return &groupMemberListResponse{
		NextUin: next,
		list:    l,
	}, nil
}

// group_member_card.get_group_member_card_info
func decodeGroupMemberInfoResponse(c *QQClient, pkt *network.Packet) (any, error) {
	rsp := pb.GroupMemberRspBody{}
	if err := proto.Unmarshal(pkt.Payload, &rsp); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal protobuf message")
	}
	if rsp.MemInfo == nil || (rsp.MemInfo.Nick == nil && rsp.MemInfo.Age == 0) {
		return nil, errors.WithStack(ErrMemberNotFound)
	}
	group := c.FindGroup(rsp.GroupCode)
	permission := Member
	if rsp.MemInfo.Uin == group.OwnerUin {
		permission = Owner
	}
	if rsp.MemInfo.Role == 2 {
		permission = Administrator
	}
	return &GroupMemberInfo{
		Group:         group,
		Uin:           rsp.MemInfo.Uin,
		Gender:        byte(rsp.MemInfo.Sex),
		Nickname:      string(rsp.MemInfo.Nick),
		CardName:      string(rsp.MemInfo.Card),
		Level:         uint16(rsp.MemInfo.Level),
		JoinTime:      rsp.MemInfo.Join,
		LastSpeakTime: rsp.MemInfo.LastSpeak,
		SpecialTitle:  string(rsp.MemInfo.SpecialTitle),
		Permission:    permission,
	}, nil
}

// LongConn.OffPicUp
func decodeOffPicUpResponse(_ *QQClient, pkt *network.Packet) (any, error) {
	rsp := cmd0x352.RspBody{}
	if err := proto.Unmarshal(pkt.Payload, &rsp); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal protobuf message")
	}
	if rsp.FailMsg != nil {
		return &imageUploadResponse{
			ResultCode: -1,
			Message:    string(rsp.FailMsg),
		}, nil
	}
	if rsp.Subcmd.Unwrap() != 1 || len(rsp.TryupImgRsp) == 0 {
		return &imageUploadResponse{
			ResultCode: -2,
		}, nil
	}
	imgRsp := rsp.TryupImgRsp[0]
	if imgRsp.Result.Unwrap() != 0 {
		return &imageUploadResponse{
			ResultCode: int32(imgRsp.Result.Unwrap()),
			Message:    string(imgRsp.FailMsg),
		}, nil
	}
	if imgRsp.FileExit.Unwrap() {
		return &imageUploadResponse{
			IsExists:   true,
			ResourceId: string(imgRsp.UpResid),
		}, nil
	}
	return &imageUploadResponse{
		ResourceId: string(imgRsp.UpResid),
		UploadKey:  imgRsp.UpUkey,
		UploadIp:   imgRsp.UpIp,
		UploadPort: imgRsp.UpPort,
	}, nil
}

// OnlinePush.PbPushTransMsg (deprecated)
func decodeOnlinePushTransPacket(c *QQClient, pkt *network.Packet) (any, error) {
	info := msg.TransMsgInfo{}
	err := proto.Unmarshal(pkt.Payload, &info)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal protobuf message")
	}
	data := binary.NewReader(info.MsgData)
	idStr := strconv.FormatInt(info.MsgUid.Unwrap(), 10)
	if _, ok := c.transCache.Get(idStr); ok {
		return nil, nil
	}
	c.transCache.Add(idStr, unit{}, time.Second*15)
	if info.MsgType.Unwrap() == 34 {
		data.ReadInt32()
		data.ReadByte()
		target := int64(uint32(data.ReadInt32()))
		typ := int32(data.ReadByte())
		operator := int64(uint32(data.ReadInt32()))

		var g *GroupInfo
		if typ == 0x02 || typ == 0x03 || typ == 0x82 || typ == 0x83 || typ == 0x01 || typ == 0x81 { //cases
			groupId := info.FromUin.Unwrap()
			group := c.FindGroupByUin(groupId)
			if group == nil {
				g, err = c.ReloadGroup(groupId)
				if err != nil {
					log.Errorf("Cannot Found OnlinePush GroupId: %v", groupId)
				}
			}
		}

		if g != nil {
			groupLeaveLock.Lock()
			defer groupLeaveLock.Unlock()
			switch typ {
			case 0x02:
				if target == c.Uin {
					c.GroupLeaveEvent.dispatch(c, &GroupLeaveEvent{Group: g})
				} else if m := g.FindMember(target); m != nil {
					g.removeMember(target)
					c.GroupMemberLeaveEvent.dispatch(c, &MemberLeaveGroupEvent{
						Group:  g,
						Member: m,
					})
				}
			case 0x03:
				if target == c.Uin {
					c.GroupLeaveEvent.dispatch(c, &GroupLeaveEvent{
						Group:    g,
						Operator: g.FindMember(operator),
					})
				} else if m := g.FindMember(target); m != nil {
					g.removeMember(target)
					c.GroupMemberLeaveEvent.dispatch(c, &MemberLeaveGroupEvent{
						Group:    g,
						Member:   m,
						Operator: g.FindMember(operator),
					})
				}
			case 0x82:
				if m := g.FindMember(target); m != nil {
					g.removeMember(target)
					c.GroupMemberLeaveEvent.dispatch(c, &MemberLeaveGroupEvent{
						Group:  g,
						Member: m,
					})
				}
			case 0x83:
				if m := g.FindMember(target); m != nil {
					g.removeMember(target)
					c.GroupMemberLeaveEvent.dispatch(c, &MemberLeaveGroupEvent{
						Group:    g,
						Member:   m,
						Operator: g.FindMember(operator),
					})
				}
			case 0x01, 0x81: // kosbot add: 群解散. 暂时这样 See https://github.com/lz1998/ricq/blob/064ddddca19aa0410e2514852e3a151fd9913371/ricq-core/src/command/online_push/decoder.rs#L86
				c.GroupDisbandEvent.dispatch(c, &GroupDisbandEvent{
					Group:    g,
					Operator: g.FindMember(operator),
					Time:     int64(info.MsgTime.Unwrap()),
				})
			}
		}
	}
	if info.MsgType.Unwrap() == 44 {
		data.ReadBytes(5)
		var4 := int32(data.ReadByte())
		var5 := int64(0)
		target := int64(uint32(data.ReadInt32()))
		if var4 != 0 && var4 != 1 {
			var5 = int64(uint32(data.ReadInt32()))
		}
		if g := c.FindGroupByUin(info.FromUin.Unwrap()); g != nil {
			if var5 == 0 && data.Len() == 1 {
				newPermission := Member
				if data.ReadByte() == 1 {
					newPermission = Administrator
				}
				mem := g.FindMember(target)
				if mem.Permission != newPermission {
					old := mem.Permission
					mem.Permission = newPermission
					c.GroupMemberPermissionChangedEvent.dispatch(c, &MemberPermissionChangedEvent{
						Group:         g,
						Member:        mem,
						OldPermission: old,
						NewPermission: newPermission,
					})
				}
			}
		}
	}
	return nil, nil
}

// ProfileService.Pb.ReqSystemMsgNew.Friend
func decodeSystemMsgFriendPacket(c *QQClient, pkt *network.Packet) (any, error) {
	rsp := structmsg.RspSystemMsgNew{}
	if err := proto.Unmarshal(pkt.Payload, &rsp); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal protobuf message")
	}
	if len(rsp.Friendmsgs) == 0 {
		return nil, nil
	}
	st := rsp.Friendmsgs[0]
	if st.Msg != nil {
		c.NewFriendRequestEvent.dispatch(c, &NewFriendRequest{
			RequestId:     st.MsgSeq,
			Message:       st.Msg.MsgAdditional,
			RequesterUin:  st.ReqUin,
			RequesterNick: st.Msg.ReqUinNick,
			client:        c,
		})
	}
	return nil, nil
}

// MessageSvc.PushForceOffline
func decodeForceOfflinePacket(c *QQClient, pkt *network.Packet) (any, error) {
	request := &jce.RequestPacket{}
	request.ReadFrom(jce.NewJceReader(pkt.Payload))
	data := &jce.RequestDataVersion2{}
	data.ReadFrom(jce.NewJceReader(request.SBuffer))
	r := jce.NewJceReader(data.Map["req_PushForceOffline"]["PushNotifyPack.RequestPushForceOffline"][1:])
	tips := r.ReadString(2)
	c.Disconnect()
	go c.DisconnectedEvent.dispatch(c, &DisconnectedEvent{Message: tips, Reconnection: false})
	return nil, nil
}

// StatSvc.ReqMSFOffline
func decodeMSFOfflinePacket(c *QQClient, _ *network.Packet) (any, error) {
	// c.lastLostMsg = "服务器端强制下线."
	c.Disconnect()
	// 这个decoder不能消耗太多时间, event另起线程处理
	go c.DisconnectedEvent.dispatch(c, &DisconnectedEvent{Message: "服务端强制下线.", Reconnection: false})
	return nil, nil
}

// OidbSvc.0xd79
func decodeWordSegmentation(_ *QQClient, pkt *network.Packet) (any, error) {
	rsp := oidb.D79RspBody{}
	err := unpackOIDBPackage(pkt.Payload, &rsp)
	if err != nil {
		return nil, err
	}
	if rsp.Content != nil {
		return rsp.Content.SliceContent, nil
	}
	return nil, errors.New("no word received")
}

func decodeSidExpiredPacket(c *QQClient, pkt *network.Packet) (any, error) {
	/*
		_, err := c.sendAndWait(c.buildRequestChangeSigPacket(true))
		if err != nil {
			return nil, errors.Wrap(err, "resign client error")
		}
		if err = c.registerClient(); err != nil {
			return nil, errors.Wrap(err, "register error")
		}
		_ = c.sendPacket(c.uniPacketWithSeq(i.SequenceId, "OnlinePush.SidTicketExpired", EmptyBytes))
	*/
	return nil, nil
}

/* unused
// LightAppSvc.mini_app_info.GetAppInfoById
func decodeAppInfoResponse(_ *QQClient, _ *incomingPacketInfo, payload []byte) (interface{}, error) {
	pkg := qweb.QWebRsp{}
	rsp := qweb.GetAppInfoByIdRsp{}
	if err := proto.Unmarshal(payload, &pkg); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal protobuf message")
	}
	if pkg.RetCode.Unwrap() != 0 {
		return nil, errors.New(pkg.ErrMsg.Unwrap())
	}
	if err := proto.Unmarshal(pkg.BusiBuff, &rsp); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal protobuf message")
	}
	return rsp.AppInfo, nil
}
*/

func ignoreDecoder(_ *QQClient, _ *network.Packet) (any, error) {
	return nil, nil
}
