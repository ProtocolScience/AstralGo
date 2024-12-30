package client

import (
	"encoding/hex"
	"github.com/Mrs4s/MiraiGo/client/internal/network"
	oldMsg "github.com/Mrs4s/MiraiGo/client/pb/msg"
	"github.com/Mrs4s/MiraiGo/client/pb/nt/media"
	ntMsg "github.com/Mrs4s/MiraiGo/client/pb/nt/message"
	"github.com/Mrs4s/MiraiGo/client/pb/trpc"
	"github.com/Mrs4s/MiraiGo/internal/proto"
	"github.com/pkg/errors"
	"runtime/debug"
)

func init() {
	decoders["trpc.msg.register_proxy.RegisterProxy.SsoInfoSync"] = decodeClientRegisterResponse
	decoders["trpc.qq_new_tech.status_svc.StatusService.SsoHeartBeat"] = decodeSsoHeartBeatResponse
	decoders["trpc.qq_new_tech.status_svc.StatusService.UnRegister"] = decodeUnregisterPacket
	decoders["trpc.qq_new_tech.status_svc.StatusService.KickNT"] = decodeKickNTPacket
	decoders["trpc.msg.olpush.OlPushService.MsgPush"] = decodeOlPushServicePacket
	decoders["OidbSvcTrpcTcp.0x9067_202"] = decode0x9067Packet
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
func decode0x9067Packet(c *QQClient, pkt *network.Packet) (any, error) {
	resp := &media.NTV2RichMediaResp{}
	err := unpackOIDBPackage(pkt.Payload, resp)
	if err != nil {
		//log.Warn("rkey read failed! Hex: " + hex.EncodeToString(pkt.Payload) + ",err: " + err.Error())
		return nil, err
	}
	var rKeyInfo = RKeyMap{}
	for _, rkey := range resp.DownloadRKey.RKeys {
		typ := RKeyType(rkey.Type.Unwrap())
		rKeyInfo[typ] = &RKeyInfo{
			RKey:       rkey.Rkey,
			RKeyType:   typ,
			CreateTime: uint64(rkey.RkeyCreateTime.Unwrap()),
			ExpireTime: uint64(rkey.RkeyCreateTime.Unwrap()) + rkey.RkeyTtlSec,
		}
	}
	return &rKeyInfo, nil
}
func decodeOlPushServicePacket(c *QQClient, pkt *network.Packet) (any, error) {
	msg := ntMsg.PushMsg{}
	err := proto.Unmarshal(pkt.Payload, &msg)
	if err != nil {
		return nil, err
	}
	pkg := msg.Message
	typ := pkg.ContentHead.Type
	defer func() {
		if r := recover(); r != nil {
			c.error("recovered from panic: %v\n%s", r, debug.Stack())
			c.error("protobuf data: %x", pkt.Payload)
		}
	}()
	if pkg.Body == nil {
		return nil, errors.New("message body is empty")
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
