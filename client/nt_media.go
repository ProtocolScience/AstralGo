package client

import (
	"errors"
	"github.com/ProtocolScience/AstralGo/client/internal/network"
	"github.com/ProtocolScience/AstralGo/client/nt"
	"github.com/ProtocolScience/AstralGo/client/pb/nt/media"
	"github.com/ProtocolScience/AstralGo/internal/proto"
	"github.com/ProtocolScience/AstralGo/utils"
	"math/rand"
)

func (c *QQClient) buildNewTechCommonGroupVoiceDownPacket(uuid string, groupId int64) (uint16, []byte) {
	return c.uniPacket("OidbSvcTrpcTcp.0x126e_200",
		c.buildNewTechCommonVoiceDownPacket(uuid, 0, groupId, 0x126e),
	)
}

func (c *QQClient) buildNewTechCommonFriendVoiceDownPacket(uuid string, friend int64) (uint16, []byte) {
	return c.uniPacket("OidbSvcTrpcTcp.0x126d_200",
		c.buildNewTechCommonVoiceDownPacket(uuid, friend, 0, 0x126d),
	)
}

func (c *QQClient) buildNewTechCommonVoiceDownPacket(uuid string, friendUin int64, groupId int64, oidb int32) []byte {
	var scene media.SceneInfo
	if groupId != 0 {
		scene = media.SceneInfo{
			RequestType:  1,
			BusinessType: 3,
			SceneType:    2,
			Group: &media.NTGroupInfo{
				GroupUin: uint32(groupId),
			},
		}
	} else {
		target := utils.UIDGlobalCaches.GetByUIN(friendUin)
		if target == nil {
			target = utils.UIDGlobalCaches.GetByUIN(c.Uin)
		}
		scene = media.SceneInfo{
			RequestType:  2,
			BusinessType: 3,
			SceneType:    1,
			C2C: &media.C2CUserInfo{
				AccountType: 2,
				TargetUid:   target.UID,
			},
		}
	}

	req := media.NTV2RichMediaReq{
		ReqHead: &media.MultiMediaReqHead{
			Common: &media.CommonHead{
				RequestId: 4,
				Command:   200,
			},
			Scene: &scene,
			Client: &media.ClientMeta{
				AgentType: 2,
			},
		},
		Download: &media.DownloadReq{
			Node: &media.IndexNode{
				Info: &media.FileInfo{
					Type: &media.FileType{
						Type:        3,
						VoiceFormat: 1,
					},
				},
				FileUuid: uuid,
				StoreId:  1,
			},
			Download: &media.DownloadExt{
				Video: &media.VideoDownloadExt{
					BusiType:    0,
					SubBusiType: 0,
					SceneType:   0,
				},
			},
		},
	}
	b, _ := proto.Marshal(&req)
	return c.packOIDBPackage(oidb, 200, b)
}
func (c *QQClient) buildNewTechCommonGroupVoiceUpPacket(info *nt.MediaParam, groupId int64) (uint16, []byte) {
	return c.uniPacket("OidbSvcTrpcTcp.0x126e_100",
		c.buildNewTechMediaUploadStorePacket(info, groupId, 0, 0x126e),
	)
}

func (c *QQClient) buildNewTechCommonFriendVoiceUpPacket(info *nt.MediaParam, friend int64) (uint16, []byte) {
	return c.uniPacket("OidbSvcTrpcTcp.0x126d_100",
		c.buildNewTechMediaUploadStorePacket(info, 0, friend, 0x126d),
	)
}

func (c *QQClient) buildNewTechCommonGroupImageUpPacket(info *nt.MediaParam, groupId int64) (uint16, []byte) {
	return c.uniPacket("OidbSvcTrpcTcp.0x11c4_100",
		c.buildNewTechMediaUploadStorePacket(info, groupId, 0, 0x11c4),
	)
}

func (c *QQClient) buildNewTechCommonFriendImageUpPacket(info *nt.MediaParam, friend int64) (uint16, []byte) {
	return c.uniPacket("OidbSvcTrpcTcp.0x11c5_100",
		c.buildNewTechMediaUploadStorePacket(info, 0, friend, 0x11c5),
	)
}

// CommonFriendVideoUp - OidbSvcTrpcTcp.0x11e9_100
// CommonGroupVideoUp - OidbSvcTrpcTcp.0x11ea_100
// CommonFriendPicUp - OidbSvcTrpcTcp.0x11c5_100
// CommonGroupPicUp - OidbSvcTrpcTcp.0x11c4_100
// CommonFriendAudioUp - OidbSvcTrpcTcp.0x126d_100
// CommonGroupAudioUp - OidbSvcTrpcTcp.0x126e_100
func (c *QQClient) buildNewTechMediaUploadStorePacket(
	info *nt.MediaParam,
	groupId int64,
	friendUin int64,
	oidb int32) []byte {

	var requestId, businessType uint32

	switch info.Type {
	case nt.IMAGE:
		businessType = 1
		requestId = 1
	case nt.AUDIO:
		businessType = 3
		requestId = 4
	case nt.VIDEO:
		businessType = 2
		requestId = 3
	default:
		businessType = 0
		requestId = 0
	}

	var scene media.SceneInfo
	if groupId != 0 {
		scene = media.SceneInfo{
			RequestType:  2,
			BusinessType: businessType,
			SceneType:    2,
			Group: &media.NTGroupInfo{
				GroupUin: uint32(groupId),
			},
		}
	} else {
		target := utils.UIDGlobalCaches.GetByUIN(friendUin)
		if target == nil {
			target = utils.UIDGlobalCaches.GetByUIN(c.Uin)
		}
		scene = media.SceneInfo{
			RequestType:  2,
			BusinessType: businessType,
			SceneType:    1,
			C2C: &media.C2CUserInfo{
				AccountType: 2,
				TargetUid:   target.UID,
			},
		}
	}

	uploadInfo := make([]*media.UploadInfo, len(info.Params))
	for i, param := range info.Params {
		fileType := media.FileType{}
		switch p := param.(type) {
		case nt.ImageParam:
			fileType = media.FileType{Type: 1, PicFormat: p.Type}
		case nt.AudioParam:
			fileType = media.FileType{Type: 3, VoiceFormat: p.Type}
		case nt.VideoParam:
			fileType = media.FileType{Type: 2, VideoFormat: p.Type}
		default:
			panic("unreachable")
		}

		uploadInfo[i] = &media.UploadInfo{
			FileInfo: &media.FileInfo{
				FileSize: uint32(param.GetSize()),
				FileHash: param.GetMD5(),
				FileSha1: param.GetSHA1(),
				FileName: param.GetFilename(),
				Type:     &fileType,
				Width:    0,
				Height:   0,
				Time:     0,
				Original: 1,
			},
			SubFileType: param.GetSubFileType(),
		}

		if img, ok := param.(nt.ImageParam); ok {
			uploadInfo[i].FileInfo.Width = img.Width
			uploadInfo[i].FileInfo.Height = img.Height
			uploadInfo[i].FileInfo.Original = 0
		} else if aud, ok := param.(nt.AudioParam); ok {
			uploadInfo[i].FileInfo.Time = aud.RecordTime
		} else if vid, ok := param.(nt.VideoParam); ok {
			uploadInfo[i].FileInfo.Time = vid.PlayTime
		}
	}

	extBizInfo := media.ExtBizInfo{}
	switch info.Type {
	case nt.IMAGE:
		extBizInfo = nt.PictureDefault()
	case nt.AUDIO:
		extBizInfo = nt.AudioDefault()
	case nt.VIDEO:
		extBizInfo = nt.VideoDefault()
	}

	req := media.NTV2RichMediaReq{
		ReqHead: &media.MultiMediaReqHead{
			Common: &media.CommonHead{
				RequestId: requestId,
				Command:   100,
			},
			Scene: &scene,
			Client: &media.ClientMeta{
				AgentType: 2,
			},
		},
		Upload: &media.UploadReq{
			UploadInfo:             uploadInfo,
			TryFastUploadCompleted: true,
			SrvSendMsg:             false,
			ClientRandomId:         rand.Uint64(),
			CompatQMsgSceneType:    scene.SceneType,
			ExtBizInfo:             &extBizInfo,
			ClientSeq:              rand.Uint32(),
			NoNeedCompatMsg:        false,
		},
	}
	b, _ := proto.Marshal(&req)
	return c.packOIDBPackage(oidb, 100, b)
}

// CommonRKeyGet - OidbSvcTrpcTcp.0x9067_202
// CommonFriendVideoUp - OidbSvcTrpcTcp.0x11e9_100
// CommonGroupVideoUp - OidbSvcTrpcTcp.0x11ea_100
// CommonFriendPicUp - OidbSvcTrpcTcp.0x11c5_100
// CommonGroupPicUp - OidbSvcTrpcTcp.0x11c4_100
// CommonFriendAudioUp - OidbSvcTrpcTcp.0x126d_100
// CommonGroupAudioUp - OidbSvcTrpcTcp.0x126e_100
// returns:
// nt.RequireUpload = 资源不存在，需要上传
// nt.FileExists = 资源已经存在，不需要上传
// nt.FileDownload = 资源下载链接获取成功
// nt.RKeyMap = 获取RKey成功
func decodeNewTechMediaResponse(_ *QQClient, pkt *network.Packet) (any, error) {
	body := &media.NTV2RichMediaResp{}
	err := unpackOIDBPackage(pkt.Payload, body)

	if err != nil {
		//log.Warn("rkey read failed! Hex: " + hex.EncodeToString(pkt.Payload) + ",err: " + err.Error())
		return nil, err
	}
	if body.RespHead == nil {
		return nil, ServerResponseError{
			Code:    1,
			Message: "decodeNewTechMediaResponse: body.RespHead == nil",
		}
	} else if body.RespHead.RetCode != 0 {
		return nil, ServerResponseError{
			Code:    int(body.RespHead.RetCode),
			Message: body.RespHead.Message,
		}
	} else if body.Upload != nil && body.Upload.MsgInfo != nil {
		ntElem, _ := proto.Marshal(body.Upload.MsgInfo)
		successInfo := nt.UploadAccess{
			MsgInfoBody: body.Upload.MsgInfo.MsgInfoBody,
			NtElem:      ntElem,
		}

		if body.Upload.UKey.Unwrap() == "" {
			return nt.FileExists{UploadAccess: successInfo}, nil
		} else {
			uploadRequired := nt.UploadTicket{
				UKey:        body.Upload.UKey.Unwrap(),
				IPv4s:       body.Upload.IPv4S, // Conversion logic needed
				SubFileType: 0,
			}

			var uploadSubRequired []nt.UploadTicket
			if body.Upload.SubFileInfos != nil {
				for _, subFileInfo := range body.Upload.SubFileInfos {
					uploadSubRequired = append(uploadSubRequired, nt.UploadTicket{
						UKey:        subFileInfo.UKey,
						IPv4s:       subFileInfo.IPv4S, // Conversion logic needed
						SubFileType: subFileInfo.SubType,
					})
				}
			}

			return nt.RequireUpload{
				UploadAccess:      successInfo,
				UploadRequired:    uploadRequired,
				UploadSubRequired: uploadSubRequired,
			}, nil
		}
	} else if body.Download != nil && body.Download.Info != nil {
		info := body.Download.Info
		return nt.FileDownload{
			DownloadAccess: nt.DownloadAccess{
				Domain:       info.Domain,
				FileUrl:      info.UrlPath,
				RKeyUrlParam: body.Download.RKeyParam,
			},
		}, nil
	} else if body.DownloadRKey != nil {
		var rKeyInfo = nt.RKeyMap{}
		for _, rKey := range body.DownloadRKey.RKeys {
			typ := nt.RKeyType(rKey.Type.Unwrap())
			rKeyInfo[typ] = &nt.RKeyInfo{
				RKey:       rKey.Rkey,
				RKeyType:   typ,
				CreateTime: uint64(rKey.RkeyCreateTime.Unwrap()),
				ExpireTime: uint64(rKey.RkeyCreateTime.Unwrap()) + rKey.RkeyTtlSec,
			}
		}
		return rKeyInfo, nil
	}
	return nil, errors.New("unhandled case")
}

/*
func (c *QQClient) NewTechUploadImage(target message.Source, img io.ReadSeeker) (message.IMessageElement, error) {
	target.
}*/

/*
func main() {
	// Example usage
	image := ImageParam{
		Width:      1920,
		Height:     1080,
		SubFileType: 0,
		Type:       1001,
		MD5:        md5.Sum([]byte("example")),
		SHA1:       sha1.Sum([]byte("example")),
		Size:       2048,
		Filename:   "image.png",
	}

	audio := AudioParam{
		RecordTime: 3,
		SubFileType: 0,
		Type:       1,
		MD5:        md5.Sum([]byte("example")),
		SHA1:       sha1.Sum([]byte("example")),
		Size:       1024,
		Filename:   "audio.amr",
	}

	video := VideoParam{
		PlayTime:   30,
		SubFileType: 0,
		Type:       1,
		MD5:        md5.Sum([]byte("example")),
		SHA1:       sha1.Sum([]byte("example")),
		Size:       4096,
		Filename:   "video.mp4",
	}

	media := MediaParam{
		Type:   IMAGE,
		Params: []DataParam{image, audio, video},
	}

	fmt.Println(media)
}*/
