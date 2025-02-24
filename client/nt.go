package client

import (
	"encoding/hex"
	"fmt"
	"github.com/ProtocolScience/AstralGo/binary"
	"github.com/ProtocolScience/AstralGo/client/internal/network"
	"github.com/ProtocolScience/AstralGo/client/pb/cmd0x6ff"
	oldMsg "github.com/ProtocolScience/AstralGo/client/pb/msg"
	"github.com/ProtocolScience/AstralGo/client/pb/notify"
	"github.com/ProtocolScience/AstralGo/client/pb/nt/event"
	ntMsg "github.com/ProtocolScience/AstralGo/client/pb/nt/message"
	"github.com/ProtocolScience/AstralGo/client/pb/nt/oidb/oidbSvcTrpcTcp0xFD4_1"
	"github.com/ProtocolScience/AstralGo/client/pb/nt/oidb/oidbSvcTrpcTcp0xFE1_2"
	"github.com/ProtocolScience/AstralGo/client/pb/nt/oidb/oidbSvcTrpcTcp0xFE5_2"
	"github.com/ProtocolScience/AstralGo/client/pb/nt/oidb/oidbSvcTrpcTcp0xFE7_3"
	"github.com/ProtocolScience/AstralGo/client/pb/trpc"
	"github.com/ProtocolScience/AstralGo/internal/proto"
	"github.com/ProtocolScience/AstralGo/utils"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"strconv"
)

var NTDecoders = map[string]func(*QQClient, *network.Packet) (any, error){
	"HttpConn.0x6ff_501": decodeConnKeyResponse,
	"trpc.msg.register_proxy.RegisterProxy.SsoInfoSync":      decodeClientRegisterResponse,
	"trpc.qq_new_tech.status_svc.StatusService.SsoHeartBeat": decodeSsoHeartBeatResponse,
	"trpc.qq_new_tech.status_svc.StatusService.UnRegister":   decodeUnregisterPacket,
	"trpc.qq_new_tech.status_svc.StatusService.KickNT":       decodeKickNTPacket,
	"trpc.msg.olpush.OlPushService.MsgPush":                  decodeOlPushServicePacket,
	"trpc.msg.register_proxy.RegisterProxy.PushParams":       decodePushParamsPacket,
	"trpc.msg.register_proxy.RegisterProxy.InfoSyncPush":     ignoreDecoder,
	"OidbSvcTrpcTcp.0x9144":                                  decodePrint,
	"OidbSvcTrpcTcp.0x92ed":                                  decodePrint,
	"OidbSvcTrpcTcp.0x9082_1":                                ignoreDecoder, //群反应
	"OidbSvcTrpcTcp.0x9082_2":                                ignoreDecoder, //群反应
	"OidbSvcTrpcTcp.0x8fc_2":                                 ignoreDecoder, //群头衔
	"OnlinePush.ReqPush":                                     ignoreDecoder, //decodeOnlinePushReqPacket与NT协议推送decodeOlPushServicePacket重复了
	"OnlinePush.PbPushTransMsg":                              ignoreDecoder, //decodeOnlinePushTransPacket与NT协议推送decodeOlPushServicePacket重复了
	"OidbSvcTrpcTcp.0xfd4_1":                                 decodeNewTechFriendGroupListResponse,
	"OidbSvcTrpcTcp.0xfe7_3":                                 decodeNewTechGetTroopMemberListResponse,
	"OidbSvcTrpcTcp.0xfe5_2":                                 decodeNewTechGetTroopListSimplyResponse,
	"OidbSvcTrpcTcp.0xfe1_2":                                 decodeNewTechUID2UINResponse,
	"OidbSvcTrpcTcp.0x11e9_100":                              decodeNewTechMediaResponse,
	"OidbSvcTrpcTcp.0x11ea_100":                              decodeNewTechMediaResponse,
	"OidbSvcTrpcTcp.0x11c5_100":                              decodeNewTechMediaResponse,
	"OidbSvcTrpcTcp.0x11c4_100":                              decodeNewTechMediaResponse,
	"OidbSvcTrpcTcp.0x126d_100":                              decodeNewTechMediaResponse,
	"OidbSvcTrpcTcp.0x126d_200":                              decodeNewTechMediaResponse,
	"OidbSvcTrpcTcp.0x126e_100":                              decodeNewTechMediaResponse,
	"OidbSvcTrpcTcp.0x126e_200":                              decodeNewTechMediaResponse,
	"OidbSvcTrpcTcp.0x9067_202":                              decodeNewTechMediaResponse,
}

func init() {
	for k, v := range NTDecoders {
		decoders[k] = v
		network.NTListCommands = append(network.NTListCommands, k)
	}
}
func decodePrint(c *QQClient, pkt *network.Packet) (any, error) {
	log.Warnf("Rev Cmd: " + pkt.CommandName)
	log.Warnf("Rev Body: " + hex.EncodeToString(pkt.Payload))
	return nil, nil
}
func decodeConnKeyResponse(c *QQClient, pkt *network.Packet) (any, error) {
	rsp := cmd0x6ff.C501RspBody{}
	if err := proto.Unmarshal(pkt.Payload, &rsp); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal protobuf message")
	}
	if c.QiDian != nil {
		c.QiDian.bigDataReqSession = &bigDataSessionInfo{
			SigSession: rsp.RspBody.SigSession,
			SessionKey: rsp.RspBody.SessionKey,
		}
		for _, srv := range rsp.RspBody.Addrs {
			if srv.ServiceType.Unwrap() == 1 {
				for _, addr := range srv.Addrs {
					c.QiDian.bigDataReqAddrs = append(c.QiDian.bigDataReqAddrs, fmt.Sprintf("%v:%v", binary.UInt32ToIPV4Address(addr.Ip.Unwrap()), addr.Port.Unwrap()))
				}
			}
		}
	}
	c.highwaySession.SigSession = rsp.RspBody.SigSession
	c.highwaySession.SessionKey = rsp.RspBody.SessionKey
	for _, srv := range rsp.RspBody.Addrs {
		if srv.ServiceType.Unwrap() == 1 {
			for _, addr := range srv.Addrs {
				c.highwaySession.AppendAddr(addr.Ip.Unwrap(), addr.Port.Unwrap())
			}
		}
	}
	return nil, nil
}

func decodeNewTechUID2UINResponse(c *QQClient, pkt *network.Packet) (any, error) {
	rsp := oidbSvcTrpcTcp0xFE1_2.Response{}
	err := unpackOIDBPackage(pkt.Payload, &rsp)
	if err != nil {
		return 0, err
	}
	return rsp.Body.Uin, nil
}
func decodePushParamsPacket(c *QQClient, pkt *network.Packet) (any, error) {
	rsp := trpc.TrpcPushParams{}
	if err := proto.Unmarshal(pkt.Payload, &rsp); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal protobuf message")
	}
	c.OnlineClients = []*OtherClientInfo{}
	for _, device := range rsp.OnlineDevices {
		name, kind := device.DeviceName.Unwrap(), device.PlatType.Unwrap()
		instId := int64(device.InstId.Unwrap())
		c.OnlineClients = append(c.OnlineClients, &OtherClientInfo{
			AppId:      instId,
			DeviceName: name,
			DeviceKind: kind,
		})
	}
	return nil, nil
}

// 只能读取1000个以内的群
func decodeNewTechGetTroopListSimplyResponse(c *QQClient, pkt *network.Packet) (any, error) {
	rsp := oidbSvcTrpcTcp0xFE5_2.Response{}
	err := unpackOIDBPackage(pkt.Payload, &rsp)
	if err != nil {
		return nil, err
	}
	l := make([]*GroupInfo, 0, len(rsp.Groups))
	for _, g := range rsp.Groups {
		l = append(l, &GroupInfo{
			Uin:            g.GroupUin,
			Code:           g.GroupUin,
			Name:           g.Info.GroupName,
			OwnerUin:       c.GetUINByUID(g.Info.GroupOwner.Uid),
			MemberCount:    uint16(g.Info.MemberCount),
			MaxMemberCount: uint16(g.Info.MemberCount),
			client:         c,
		})
	}
	return l, nil
}
func decodeNewTechGetTroopMemberListResponse(_ *QQClient, pkt *network.Packet) (any, error) {
	rsp := oidbSvcTrpcTcp0xFE7_3.Response{}
	err := unpackOIDBPackage(pkt.Payload, &rsp)
	if err != nil {
		return nil, err
	}
	l := make([]*GroupMemberInfo, 0, len(rsp.Members))
	for _, m := range rsp.Members {
		permission := Member
		if m.Permission == 1 {
			permission = Owner
		} else if m.Permission == 2 {
			permission = Administrator
		}
		level := 0
		if m.Level != nil {
			level = int(m.Level.Level)
		}
		l = append(l, &GroupMemberInfo{
			Uid:             m.Uin.Uid,
			Uin:             m.Uin.Uin,
			Nickname:        m.MemberName,
			Gender:          1, //TODO 读取群成员性别
			CardName:        m.MemberCard.MemberCard,
			Level:           uint16(level),
			JoinTime:        int64(m.JoinTimestamp),
			LastSpeakTime:   int64(m.LastMsgTimestamp),
			SpecialTitle:    m.SpecialTitle,
			ShutUpTimestamp: int64(m.ShutUpTimestamp),
			Permission:      permission,
		})
	}
	return &NTGroupMemberListResponse{
		nextToken: rsp.Token,
		list:      l,
	}, nil
}
func decodeNewTechFriendGroupListResponse(_ *QQClient, pkt *network.Packet) (any, error) {
	rsp := oidbSvcTrpcTcp0xFD4_1.Response{}
	err := unpackOIDBPackage(pkt.Payload, &rsp)
	if err != nil {
		log.Warn("decodeNewTechFriendGroupListResponse failed! Hex: " + hex.EncodeToString(pkt.Payload) + ",err: " + err.Error())
		return nil, err
	}
	l := make([]*FriendInfo, 0, len(rsp.Friends))
	//好友分组 rsp.Groups
	for _, f := range rsp.Friends {
		var foundAddit *oidbSvcTrpcTcp0xFD4_1.FriendAdditional = nil
		for _, addit := range f.Additional {
			if addit.Type == 1 {
				foundAddit = addit
			}
		}
		if foundAddit == nil {
			continue
		}
		properties := foundAddit.Layer1.Properties
		var nick = ""
		var remark = ""
		for _, prop := range properties {
			if prop.Code == 20002 {
				nick = prop.Value
			} else if prop.Code == 103 {
				remark = prop.Value
			}
		}
		l = append(l, &FriendInfo{
			Uid:      f.Uid,
			Uin:      f.Uin,
			Nickname: nick,
			Remark:   remark,
			FaceId:   0,
		})
	}
	return &NTFriendListResponse{
		ContinueToken: rsp.ContinueToken,
		List:          l,
	}, nil
}
func decoderObserver(c *QQClient, pkt *network.Packet) (any, error) {
	c.error("decoderObserver: %s", hex.EncodeToString(pkt.Payload))
	return nil, nil
}
func decodeSsoHeartBeatResponse(c *QQClient, pkt *network.Packet) (any, error) {
	if len(pkt.Payload) == 0 {
		return nil, errors.New("failed to send sso heartbeat")
	}
	return nil, nil
}
func decodeClientRegisterResponse(c *QQClient, pkt *network.Packet) (any, error) {
	rsp := trpc.SsoInfoSyncRespBody{}
	if err := proto.Unmarshal(pkt.Payload, &rsp); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal protobuf message")
	}
	if rsp.RetData == nil {
		return nil, &ServerResponseError{
			Code:    1002,
			Message: "error requesting register with unknown error.",
		}
	}
	if rsp.RetData.Message.Unwrap() == "register success" {
		return nil, nil
	}
	c.error("reg error: %v", rsp.RetData.Message)
	return nil, &ServerResponseError{
		Code:    1002,
		Message: "error requesting register with: " + rsp.RetData.Message.Unwrap(),
	}
}

func decodeUnregisterPacket(c *QQClient, pkt *network.Packet) (any, error) {
	resp := &trpc.UnRegisterResp{}
	err := proto.Unmarshal(pkt.Payload, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
func decodeKickNTPacket(c *QQClient, pkt *network.Packet) (any, error) {
	resp := &trpc.NTKickEvent{}
	err := proto.Unmarshal(pkt.Payload, resp)
	if err != nil {
		return nil, err
	}
	//	log.Warnf("NT OFFLINE: %s", resp.Tips.Unwrap())
	c.Disconnect()
	go c.DisconnectedEvent.dispatch(c, &DisconnectedEvent{Message: resp.Tips.Unwrap(), Reconnection: false})
	return nil, nil
}
func decodeOlPushServicePacket(c *QQClient, pkt *network.Packet) (any, error) {
	msg := ntMsg.PushMsg{}
	err := proto.Unmarshal(pkt.Payload, &msg)
	if err != nil {
		return nil, err
	}
	pkg := msg.Message
	typ := pkg.ContentHead.Type
	/*
		if pkg.Body == nil {
			return nil, errors.New("message body is empty, type:" + strconv.Itoa(int(typ)))
		}*/
	if pkg.Body == nil {
		return nil, nil
	}

	c.WaitInit(true)

	if pkg.ResponseHead != nil {
		utils.UIDGlobalCaches.Add(pkg.ResponseHead.FromUid.Unwrap(), int64(pkg.ResponseHead.FromUin))
		utils.UIDGlobalCaches.Add(pkg.ResponseHead.ToUid.Unwrap(), int64(pkg.ResponseHead.ToUin))
	}
	switch typ {
	case 82: // group msg
		richText := oldMsg.RichText{}
		if proto.Unmarshal(pkg.Body.RichText, &richText) != nil {
			richText = oldMsg.RichText{}
		}
		convertedMsg := oldMsg.Message{
			Head: &oldMsg.MessageHead{
				FromUin:   proto.Some(int64(pkg.ResponseHead.FromUin)),
				ToUin:     proto.Some(int64(pkg.ResponseHead.ToUin)),
				MsgType:   proto.Some(int32(pkg.ResponseHead.Type)),
				C2CCmd:    proto.Some(int32(pkg.ContentHead.C2CCmd.Unwrap())),
				MsgSeq:    proto.Some(int32(pkg.ContentHead.Sequence.Unwrap())),
				MsgTime:   proto.Some(int32(pkg.ContentHead.TimeStamp.Unwrap())),
				MsgUid:    proto.Some(int64(pkg.ContentHead.MsgId.Unwrap())),
				GroupName: proto.Some(pkg.ResponseHead.Grp.GroupName),
				GroupInfo: &oldMsg.GroupInfo{
					GroupCode: proto.Some(int64(pkg.ResponseHead.Grp.GroupUin)),
					GroupName: []byte(pkg.ResponseHead.Grp.GroupName),
					GroupCard: proto.Some(pkg.ResponseHead.Grp.MemberName),
				},
				FromInstid: proto.Some(int32(pkg.ResponseHead.SigMap)),
				FromAppid:  proto.Some(int32(pkg.ResponseHead.Type)),
			},
			Content: &oldMsg.ContentHead{
				DivSeq: proto.Some(int32(pkg.ContentHead.DivSeq.Unwrap())),
			},
			Body: &oldMsg.MessageBody{
				RichText:          &richText,
				MsgContent:        pkg.Body.MsgContent,
				MsgEncryptContent: pkg.Body.MsgEncryptContent,
			},
		}
		grpMsg := c.parseGroupMessage(&convertedMsg)
		if grpMsg.Sender.Uin == c.Uin {
			c.dispatchGroupMessageReceiptEvent(&groupMessageReceiptEvent{
				Rand: richText.Attr.Random.Unwrap(),
				Seq:  int32(pkg.ContentHead.Sequence.Unwrap()),
				Msg:  grpMsg,
			})
			c.SelfGroupMessageEvent.dispatch(c, grpMsg)
		} else {
			c.GroupMessageEvent.dispatch(c, grpMsg)
		}
		return nil, nil
	case 166, 167, 208, 141, 529: // 166 for private msg, 208 for private record, 529 for private file
		richText := oldMsg.RichText{}
		if proto.Unmarshal(pkg.Body.RichText, &richText) != nil || len(richText.Elems) == 0 {
			return nil, nil
		}
		convertedMsg := oldMsg.Message{
			Head: &oldMsg.MessageHead{
				FromUin:    proto.Some(int64(pkg.ResponseHead.FromUin)),
				ToUin:      proto.Some(int64(pkg.ResponseHead.ToUin)),
				MsgType:    proto.Some(int32(pkg.ContentHead.Type)),
				C2CCmd:     proto.Some(int32(pkg.ContentHead.C2CCmd.Unwrap())),
				MsgSeq:     proto.Some(int32(pkg.ContentHead.Sequence.Unwrap())),
				MsgTime:    proto.Some(int32(pkg.ContentHead.TimeStamp.Unwrap())),
				MsgUid:     proto.Some(int64(pkg.ContentHead.MsgId.Unwrap())),
				FromInstid: proto.Some(int32(pkg.ResponseHead.SigMap)),
				FromAppid:  proto.Some(int32(pkg.ResponseHead.Type)),
				C2CTmpMsgHead: func() *oldMsg.C2CTempMessageHead {
					if pkg.ResponseHead.Forward != nil {
						return &oldMsg.C2CTempMessageHead{
							GroupUin: proto.Some(int64(pkg.ResponseHead.Forward.GroupUin.Unwrap())),
						}
					}
					return nil
				}(),
			},
			Content: &oldMsg.ContentHead{
				DivSeq: proto.Some(int32(pkg.ContentHead.DivSeq.Unwrap())),
			},
			Body: &oldMsg.MessageBody{
				RichText:          &richText,
				MsgContent:        pkg.Body.MsgContent,
				MsgEncryptContent: pkg.Body.MsgEncryptContent,
			},
		}
		if typ == 166 || typ == 208 || typ == 529 {
			prvMsg := c.parsePrivateMessage(&convertedMsg)
			if prvMsg.Sender.Uin != c.Uin {
				c.PrivateMessageEvent.dispatch(c, prvMsg)
			} else {
				c.SelfPrivateMessageEvent.dispatch(c, prvMsg)
			}
		} else {
			genTempSessionInfo := func() *TempSessionInfo {
				if convertedMsg.Head.C2CTmpMsgHead.ServiceType.Unwrap() == 0 {
					group := c.FindGroup(convertedMsg.Head.C2CTmpMsgHead.GroupCode.Unwrap())
					if group == nil {
						return nil
					}
					return &TempSessionInfo{
						Source:    GroupSource,
						GroupCode: group.Code,
						Sender:    convertedMsg.Head.FromUin.Unwrap(),
						client:    c,
					}
				}
				info := &TempSessionInfo{
					Source: 0,
					Sender: convertedMsg.Head.FromUin.Unwrap(),
					sig:    convertedMsg.Head.C2CTmpMsgHead.Sig,
					client: c,
				}
				switch convertedMsg.Head.C2CTmpMsgHead.ServiceType.Unwrap() {
				case 1:
					info.Source = MultiChatSource
				case 130:
					info.Source = AddressBookSource
				case 132:
					info.Source = HotChatSource
				case 134:
					info.Source = SystemMessageSource
				case 201:
					info.Source = ConsultingSource
				default:
					return nil
				}
				return info
			}
			session := genTempSessionInfo()
			if session != nil {
				if convertedMsg.Head.FromUin.Unwrap() != c.Uin {
					c.TempMessageEvent.dispatch(c, &TempMessageEvent{
						Message: c.parseTempMessage(&convertedMsg),
						Session: session,
					})
				}
			}
		}
		return nil, nil
	case 0x210: // friend event, 528
		subType := int64(pkg.ContentHead.SubType.Unwrap())
		protobuf := pkg.Body.MsgContent

		// 0xB3 好友验证消息，申请，同意都有
		// 0xE2 new friend 主动加好友且对方同意
		if subType == 0xE2 || subType == 0xB3 {
			newFriend := event.NewFriend{}
			if e := proto.Unmarshal(protobuf, &newFriend); e == nil { //NT格式解析
				frd := &FriendInfo{
					Uin:      c.GetUINByUID(newFriend.Info.Uid),
					Nickname: newFriend.Info.NickName,
				}
				c.FriendList = append(c.FriendList, frd)
				c.NewFriendEvent.dispatch(c, &NewFriendEvent{Friend: frd})
				break
			}
		}

		//旧格式解析
		if decoder, ok := msg0x210Decoders[subType]; ok {
			if e := decoder(c, protobuf); e != nil {
				return nil, errors.Wrap(e, "decode online push 0x210 error")
			}
			log.Debugf("0x210: subType: %d, passed", subType)
		} else {
			c.debug("unknown online push 0x210 sub type 0x%v", strconv.FormatInt(subType, 16))
		}
		return nil, nil
	case 0x2DC: // grp event, 732
		subType := pkg.ContentHead.SubType.Unwrap()
		switch subType {
		case 0x10, 0x11, 0x14, 0x15: // group notify msg
			b := event.NotifyMsgBody{}
			reader := binary.NewReader(pkg.Body.MsgContent)
			reader.ReadBytes(7)
			err = proto.Unmarshal(reader.ReadAvailable(), &b)
			if err != nil {
				return nil, err
			}
			groupCode := b.OptGroupId
			if b.OptMsgRecall != nil {
				for _, rm := range b.OptMsgRecall.RecalledMsgList {
					if rm.MsgType == 2 {
						continue
					}
					c.GroupMessageRecalledEvent.dispatch(c, &GroupMessageRecalledEvent{
						GroupCode:   groupCode,
						OperatorUin: c.GetUINByUID(b.OptMsgRecall.Uid),
						AuthorUin:   c.GetUINByUID(rm.AuthorUid),
						MessageId:   rm.Seq,
						Time:        rm.Time,
					})
				}
			}
			if b.OptGeneralGrayTip != nil {
				tip := notify.GeneralGrayTipInfo{}
				err = proto.Unmarshal(b.OptGeneralGrayTip, &tip)
				if err != nil {
					return nil, err
				}
				c.grayTipProcessor(groupCode, &tip)
			}
			if b.OptMsgRedTips != nil {
				if b.OptMsgRedTips.LuckyFlag == 1 { // 运气王提示
					c.GroupNotifyEvent.dispatch(c, &GroupRedBagLuckyKingNotifyEvent{
						GroupCode: groupCode,
						Sender:    int64(b.OptMsgRedTips.SenderUin),
						LuckyKing: int64(b.OptMsgRedTips.LuckyUin),
					})
				}
			}
			if b.QqGroupDigestMsg != nil {
				digest := b.QqGroupDigestMsg
				c.GroupDigestEvent.dispatch(c, &GroupDigestEvent{
					GroupCode:         int64(digest.GroupCode),
					MessageID:         int32(digest.Seq),
					InternalMessageID: int32(digest.Random),
					OperationType:     digest.OpType,
					OperateTime:       digest.OpTime,
					SenderUin:         c.GetUINByUID(digest.Sender),
					OperatorUin:       c.GetUINByUID(digest.DigestOper),
					SenderNick:        string(digest.SenderNick),
					OperatorNick:      string(digest.OperNick),
				})
			}
			if b.OptMsgGraytips != nil {
				tip := notify.AIOGrayTipsInfo{}
				err = proto.Unmarshal(b.OptMsgGraytips, &tip)
				if err != nil {
					return nil, err
				}
				c.msgGrayTipProcessor(groupCode, &tip)
			}
			log.Debugf("0x2DC: subType: %d, passed", subType)
		case 0x0c: // 群内禁言
			b := event.GroupMuteEvent{}
			err = proto.Unmarshal(pkg.Body.MsgContent, &b)
			if err != nil {
				return nil, err
			}
			c.GroupMuteEvent.dispatch(c, &GroupMuteEvent{
				GroupCode:   b.GroupUin,
				OperatorUin: c.GetUINByUID(b.OperatorUid),
				TargetUin:   c.GetUINByUID(b.Data.State.TargetUid),
				Time:        b.Data.State.Duration,
			})
			log.Debugf("0x2DC: subType: %d, passed", subType)
		case 0x21: // 入群事件 (see troopAddMemberBroadcastDecoder)
			b := ntMsg.GroupChange{}
			err = proto.Unmarshal(pkg.Body.MsgContent, &b)
			groupJoinLock.Lock()
			defer groupJoinLock.Unlock()
			groupId := b.GroupUin
			group := c.FindGroupByUin(int64(groupId))
			uin := c.GetUINByUID(b.MemberUid)
			if uin == c.Uin {
				if group == nil {
					groupInfo, e := c.ReloadGroup(int64(groupId))
					if e == nil {
						c.GroupJoinEvent.dispatch(c, groupInfo)
					} else {
						log.Errorf("Cannot Found Joined GroupId: %v", groupId)
					}
				}
			} else {
				if group != nil && group.FindMember(uin) == nil {
					mem, e := c.GetMemberInfo(group.Code, uin)
					if e == nil {
						group.Update(func(info *GroupInfo) {
							info.Members = append(info.Members, mem)
							info.sort()
						})
						c.GroupMemberJoinEvent.dispatch(c, &MemberJoinGroupEvent{
							Group:  group,
							Member: mem,
						})
					} else {
						c.debug("failed to fetch new member info: %v", err)
					}
				}
			}
		case 0x22: // 离群事件( TODO : 群解散等，都有，但是需要进一步发包 OidbSvcTrpcTcp.0x10c0_1 才能得知
			groupLeaveLock.Lock()
			defer groupLeaveLock.Unlock()
			b := ntMsg.GroupChange{}
			err = proto.Unmarshal(pkg.Body.MsgContent, &b)
			if b.DecreaseType == 3 && b.Operator != nil {
				Operator := ntMsg.OperatorInfo{}
				err = proto.Unmarshal(b.Operator, &Operator)
				if err != nil {
					return nil, err
				}
				b.Operator = utils.S2B(Operator.OperatorField1.OperatorUid)
			}
			var g *GroupInfo
			groupId := (int64)(b.GroupUin)
			group := c.FindGroupByUin(groupId)
			if group == nil {
				g, err = c.ReloadGroup(groupId)
				if err != nil {
					log.Errorf("Cannot Found OnlinePush GroupId: %v, type: %v, body: %s", groupId, typ, hex.EncodeToString(pkt.Payload))
				}
			}
			if g == nil {
				break
			}
			uin := c.GetUINByUID(b.MemberUid)
			var op *GroupMemberInfo
			if len(b.Operator) > 0 {
				op = g.FindMember(c.GetUINByUID(string(b.Operator)))
			}
			if uin == c.Uin {
				c.GroupLeaveEvent.dispatch(c, &GroupLeaveEvent{
					Group:    g,
					Operator: op,
				})
			} else if m := g.FindMember(uin); m != nil {
				g.removeMember(uin)
				c.GroupMemberLeaveEvent.dispatch(c, &MemberLeaveGroupEvent{
					Group:    g,
					Member:   m,
					Operator: op,
				})
			}
		case 0x2C: // 群权限变动
			pb := ntMsg.GroupAdmin{}
			err = proto.Unmarshal(pkg.Body.MsgContent, &pb)
			if err != nil {
				return nil, err
			}
			var uin int64
			newPermission := Member
			if pb.Body.ExtraDisable != nil {
				uin = c.GetUINByUID(pb.Body.ExtraDisable.AdminUid)
			} else if pb.Body.ExtraEnable != nil {
				newPermission = Administrator
				uin = c.GetUINByUID(pb.Body.ExtraEnable.AdminUid)
			}
			if g := c.FindGroupByUin(int64(pb.GroupUin)); g != nil {
				mem := g.FindMember(uin)
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
		default:
			c.debug("unknown online push 0x2DC sub type 0x%v", strconv.FormatInt(int64(subType), 16))
		}
		return nil, nil
		/*
			case 33: // member increase
				pb := message.GroupChange{}
				err = proto.Unmarshal(pkg.Body.MsgContent, &pb)
				if err != nil {
					return nil, err
				}
				ev := eventConverter.ParseMemberIncreaseEvent(&pb)
				_ = c.ResolveUin(ev)
				if ev.UserUin == c.Uin { // bot 进群
					_ = c.RefreshAllGroupsInfo()
					c.GroupJoinEvent.dispatch(c, ev)
				} else {
					_ = c.RefreshGroupMemberCache(ev.GroupUin, ev.UserUin)
					c.GroupMemberJoinEvent.dispatch(c, ev)
				}
				return nil, nil
			case 34: // member decrease
				pb := message.GroupChange{}
				err = proto.Unmarshal(pkg.Body.MsgContent, &pb)
				if err != nil {
					return nil, err
				}
				// 3 是bot自身被踢出，Operator字段会是一个protobuf
				if pb.DecreaseType == 3 && pb.Operator != nil {
					Operator := message.OperatorInfo{}
					err = proto.Unmarshal(pb.Operator, &Operator)
					if err != nil {
						return nil, err
					}
					pb.Operator = utils.S2B(Operator.OperatorField1.OperatorUid)
				}
				ev := eventConverter.ParseMemberDecreaseEvent(&pb)
				_ = c.ResolveUin(ev)
				if ev.UserUin == c.Uin {
					c.GroupLeaveEvent.dispatch(c, ev)
				} else {
					c.GroupMemberLeaveEvent.dispatch(c, ev)
				}
				return nil, nil
			case 44: // group admin changed
				pb := message.GroupAdmin{}
				err = proto.Unmarshal(pkg.Body.MsgContent, &pb)
				if err != nil {
					return nil, err
				}
				ev := eventConverter.ParseGroupMemberPermissionChanged(&pb)
				_ = c.ResolveUin(ev)
				_ = c.RefreshGroupMemberCache(ev.GroupUin, ev.UserUin)
				c.GroupMemberPermissionChangedEvent.dispatch(c, ev)
			case 84: // group request join notice
				pb := message.GroupJoin{}
				err = proto.Unmarshal(pkg.Body.MsgContent, &pb)
				if err != nil {
					return nil, err
				}
				ev := eventConverter.ParseRequestJoinNotice(&pb)
				_ = c.ResolveUin(ev)
				user, _ := c.FetchUserInfo(ev.UserUID)
				if user != nil {
					ev.UserUin = user.Uin
					ev.TargetNick = user.Nickname
				}
				commonRequests, reqErr := c.GetGroupSystemMessages(false, 20, ev.GroupUin)
				filteredRequests, freqErr := c.GetGroupSystemMessages(true, 20, ev.GroupUin)
				if reqErr == nil && freqErr == nil {
					for _, request := range append(commonRequests.JoinRequests, filteredRequests.JoinRequests...) {
						if request.TargetUID == ev.UserUID && !request.Checked {
							ev.RequestSeq = request.Sequence
							ev.Answer = request.Comment
						}
					}
				}
				c.GroupMemberJoinRequestEvent.dispatch(c, ev)
				return nil, nil
			case 525: // group request invitation notice
				pb := message.GroupInvitation{}
				err = proto.Unmarshal(pkg.Body.MsgContent, &pb)
				if err != nil {
					return nil, err
				}
				if pb.Cmd != 87 {
					return nil, nil
				}
				ev := eventConverter.ParseRequestInvitationNotice(&pb)
				_ = c.ResolveUin(ev)
				user, _ := c.FetchUserInfo(ev.UserUID)
				if user != nil {
					ev.UserUin = user.Uin
					ev.TargetNick = user.Nickname
				}
				c.GroupMemberJoinRequestEvent.dispatch(c, ev)
				return nil, nil
			case 87: // group invite notice
				pb := message.GroupInvite{}
				err = proto.Unmarshal(pkg.Body.MsgContent, &pb)
				if err != nil {
					return nil, err
				}
				ev := eventConverter.ParseInviteNotice(&pb)
				group, err := c.FetchGroupInfo(ev.GroupUin, true)
				if err == nil {
					ev.GroupName = group.GroupName
				}
				_ = c.ResolveUin(ev)
				user, _ := c.FetchUserInfo(ev.InvitorUID)
				if user != nil {
					ev.InvitorUin = user.Uin
					ev.InvitorNick = user.Nickname
				}
				commonRequests, reqErr := c.GetGroupSystemMessages(false, 20, ev.GroupUin)
				filteredRequests, freqErr := c.GetGroupSystemMessages(true, 20, ev.GroupUin)
				if reqErr == nil && freqErr == nil {
					for _, request := range append(commonRequests.InvitedRequests, filteredRequests.InvitedRequests...) {
						if !request.Checked {
							ev.RequestSeq = request.Sequence
							break
						}
					}
				}
				c.GroupInvitedEvent.dispatch(c, ev)
				return nil, nil
			case 0x210: // friend event, 528
				subType := pkg.ContentHead.SubType.Unwrap()
				switch subType {
				case 35: // friend request notice
					pb := message.FriendRequest{}
					err = proto.Unmarshal(pkg.Body.MsgContent, &pb)
					if err != nil {
						return nil, err
					}
					if pb.Info == nil {
						break
					}
					ev := eventConverter.ParseFriendRequestNotice(&pb)
					user, _ := c.FetchUserInfo(ev.SourceUID)
					if user != nil {
						ev.SourceUin = user.Uin
						ev.SourceNick = user.Nickname
					}
					c.NewFriendRequestEvent.dispatch(c, ev)
					return nil, nil
				case 138: // friend recall
					pb := message.FriendRecall{}
					err = proto.Unmarshal(pkg.Body.MsgContent, &pb)
					if err != nil {
						return nil, err
					}
					ev := eventConverter.ParseFriendRecallEvent(&pb)
					_ = c.ResolveUin(ev)
					c.FriendRecallEvent.dispatch(c, ev)
					return nil, nil
				case 39: // friend rename
					pb := message.FriendRenameMsg{}
					err = proto.Unmarshal(pkg.Body.MsgContent, &pb)
					if err != nil {
						return nil, err
					}
					if pb.Body.Field2 == 20 { // friend name update
						ev := eventConverter.ParseFriendRenameEvent(&pb)
						_ = c.ResolveUin(ev)
						c.RenameEvent.dispatch(c, ev)
					} // 40 grp name
					return nil, nil
				case 29:
					pb := message.SelfRenameMsg{}
					err = proto.Unmarshal(pkg.Body.MsgContent, &pb)
					if err != nil {
						return nil, err
					}
					c.RenameEvent.dispatch(c, eventConverter.ParseSelfRenameEvent(&pb, &c.transport.Sig))
					return nil, nil
				case 290: // greyTip
					pb := message.GeneralGrayTipInfo{}
					err = proto.Unmarshal(pkg.Body.MsgContent, &pb)
					if err != nil {
						return nil, err
					}
					if pb.BusiType == 12 {
						c.FriendNotifyEvent.dispatch(c, eventConverter.ParsePokeEvent(&pb))
					}
				case 226: // 好友验证消息，申请，同意都有
				case 179: // new friend 主动加好友且对方同意
					pb := message.NewFriend{}
					err = proto.Unmarshal(pkg.Body.MsgContent, &pb)
					if err != nil {
						return nil, err
					}
					ev := eventConverter.ParseNewFriendEvent(&pb)
					_ = c.ResolveUin(ev)
					c.NewFriendEvent.dispatch(c, ev)
				default:
					c.debug("unknown subtype %d of type 0x210, proto data: %x", subType, pkg.Body.MsgContent)
				}
			case 0x2DC: // grp event, 732
				subType := pkg.ContentHead.SubType.Unwrap()
				switch subType {
				case 21: // set essence
					reader := binary.NewReader(pkg.Body.MsgContent)
					_ = reader.ReadU32() // group uin
					reader.SkipBytes(1)  // unknown byte
					pb := message.NotifyMessageBody{}
					err = proto.Unmarshal(reader.ReadBytesWithLength("u16", false), &pb)
					if err != nil {
						return nil, err
					}
					c.GroupDigestEvent.dispatch(c, eventConverter.ParseGroupDigestEvent(&pb))
					return nil, nil
				case 20: // group greyTip
					reader := binary.NewReader(pkg.Body.MsgContent)
					groupUin := reader.ReadU32() // group uin
					reader.SkipBytes(1)          // unknown byte
					pb := message.NotifyMessageBody{}
					err = proto.Unmarshal(reader.ReadBytesWithLength("u16", false), &pb)
					if err != nil {
						return nil, err
					}
					if pb.GrayTipInfo.BusiType == 12 { // poke
						c.GroupNotifyEvent.dispatch(c, eventConverter.ParseGroupPokeEvent(&pb, groupUin))
					}
					return nil, nil
				case 17: // recall
					reader := binary.NewReader(pkg.Body.MsgContent)
					_ = reader.ReadU32() // group uin
					_ = reader.ReadU8()  // reserve
					pb := message.NotifyMessageBody{}
					err = proto.Unmarshal(reader.ReadBytesWithLength("u16", false), &pb)
					if err != nil {
						return nil, err
					}
					ev := eventConverter.ParseGroupRecallEvent(&pb)
					_ = c.ResolveUin(ev)
					c.GroupRecallEvent.dispatch(c, ev)
					return nil, nil
				case 16: // group name update & member special title update & group reaction
					reader := binary.NewReader(pkg.Body.MsgContent)
					groupUin := reader.ReadU32()
					reader.SkipBytes(1)
					pb := message.NotifyMessageBody{}
					err = proto.Unmarshal(reader.ReadBytesWithLength("u16", false), &pb)
					if err != nil {
						return nil, err
					}
					switch pb.Field13 {
					case 6: // GroupMemberSpecialTitle
						epb := message.GroupSpecialTitle{}
						err := proto.Unmarshal(pb.EventParam, &epb)
						if err != nil {
							return nil, err
						}
						c.MemberSpecialTitleUpdatedEvent.dispatch(c, eventConverter.ParseGroupMemberSpecialTitleUpdatedEvent(&epb, groupUin))
					case 12: // group name update
						r := binary.NewReader(pb.EventParam)
						r.SkipBytes(3)
						ev := eventConverter.ParseGroupNameUpdatedEvent(&pb, string(r.ReadBytesWithLength("u8", false)))
						_ = c.ResolveUin(ev)
						c.GroupNameUpdatedEvent.dispatch(c, ev)
					case 35: // group reaction
						r := binary.NewReader(pkg.Body.MsgContent)
						r.ReadU32()
						r.ReadBytes(1)
						rpb := message.GroupReaction{}
						err := proto.Unmarshal(r.ReadBytesWithLength("u16", false), &rpb)
						if err != nil {
							return nil, err
						}
						ev := eventConverter.ParseGroupReactionEvent(&rpb)
						_ = c.ResolveUin(ev)
						c.GroupReactionEvent.dispatch(c, ev)
					}
				case 12: // mute
					pb := message.GroupMute{}
					err = proto.Unmarshal(pkg.Body.MsgContent, &pb)
					if err != nil {
						return nil, err
					}
					ev := eventConverter.ParseGroupMuteEvent(&pb)
					_ = c.ResolveUin(ev)
					c.GroupMuteEvent.dispatch(c, ev)
					return nil, nil
				default:
					c.debug("Unsupported group event, subType: %v, proto data: %x", subType, pkg.Body.MsgContent)
				}*/
	default:
		c.debug("Unsupported message type: %v, proto data: %x", typ, pkg.Body.MsgContent)
	}

	return nil, nil
}
