package client

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"github.com/ProtocolScience/AstralGo/client/nt"
	"github.com/ProtocolScience/AstralGo/client/pb/msg"
	log "github.com/sirupsen/logrus"
	"io"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/ProtocolScience/AstralGo/binary"
	"github.com/ProtocolScience/AstralGo/client/internal/highway"
	"github.com/ProtocolScience/AstralGo/client/internal/network"
	"github.com/ProtocolScience/AstralGo/client/pb/cmd0x346"
	"github.com/ProtocolScience/AstralGo/client/pb/cmd0x388"
	"github.com/ProtocolScience/AstralGo/client/pb/pttcenter"
	"github.com/ProtocolScience/AstralGo/internal/proto"
	"github.com/ProtocolScience/AstralGo/message"
	"github.com/ProtocolScience/AstralGo/utils"
)

func init() {
	decoders["PttCenterSvr.ShortVideoDownReq"] = decodePttShortVideoDownResponse
	decoders["PttCenterSvr.GroupShortVideoUpReq"] = decodeGroupShortVideoUploadResponse
}

var pttWaiter = utils.NewUploadWaiter()

func c2cPttExtraInfo() []byte {
	w := binary.SelectWriter()
	defer binary.PutWriter(w)
	w.WriteByte(2) // tlv count
	{
		w.WriteByte(8)
		w.WriteUInt16(4)
		w.WriteUInt32(1) // codec
	}
	{
		w.WriteByte(9)
		w.WriteUInt16(4)
		w.WriteUInt32(0) // 时长
	}
	w.WriteByte(10)
	reserveInfo := []byte{0x08, 0x00, 0x28, 0x00, 0x38, 0x00} // todo
	w.WriteBytesShort(reserveInfo)
	return append([]byte(nil), w.Bytes()...)
}

// UploadVoice 将语音数据使用群语音通道上传到服务器, 返回 message.NewTechVoiceElement 可直接发送
func (c *QQClient) UploadVoice(target message.Source, voice io.ReadSeeker, during uint32) (*message.NewTechVoiceElement, error) {
	switch target.SourceType {
	case message.SourceGroup, message.SourcePrivate:
		// ok
	default:
		return nil, errors.New("unsupported source type")
	}
	_, _ = voice.Seek(0, io.SeekStart)
	hash, sha1, length, err := utils.ComputeMd5Sha1AndLength(voice)
	if err != nil {
		return nil, err
	}
	_, _ = voice.Seek(0, io.SeekStart)
	fileName := strings.ToUpper(hex.EncodeToString(hash)) + ".amr"
	cacheKey := fmt.Sprintf("%v-%v", target.SourceType, fileName)
	if cacheData, ok := c.voiceUploadCache.Get(cacheKey); ok { //短暂缓存上传数据，防止同一个语音被反复上传
		return &cacheData, nil
	}
	if during == 0 {
		log.Debug("zero voice detected, setting to 8 seconds")
		during = 8
	}
	media := nt.MediaParam{
		Type: nt.AUDIO,
		Params: []nt.DataParam{
			nt.AudioParam{
				SubFileType: 0,
				Type:        1,
				MD5:         hash,
				SHA1:        sha1,
				Size:        int64(length),
				Filename:    fileName,
				RecordTime:  during,
			},
		},
	}
	var resp interface{}
	var commandId int32
	var business uint32
	switch target.SourceType {
	case message.SourceGroup:
		commandId = 1008
		business = nt.BusinessGroupAudio
		resp, err = c.sendAndWait(c.buildNewTechCommonGroupVoiceUpPacket(&media, target.PrimaryID))
		if err != nil {
			return nil, err
		}
	case message.SourcePrivate:
		commandId = 1007
		business = nt.BusinessFriendAudio
		resp, err = c.sendAndWait(c.buildNewTechCommonFriendVoiceUpPacket(&media, target.PrimaryID))
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.Wrap(err, "unsupported source type")
	}

	var access *nt.UploadAccess = nil
	switch resp.(type) {
	case nt.FileExists:
		r := resp.(nt.FileExists)
		access = &r.UploadAccess
		break
	case nt.RequireUpload:
		r := resp.(nt.RequireUpload)
		access = &r.UploadAccess
		ext, e := resp.(nt.RequireUpload).RichMediaHighwayExt(voice, length, 0)
		_, _ = voice.Seek(0, io.SeekStart)
		input := highway.Transaction{
			CommandID: commandId,
			Body:      voice,
			Size:      int64(length),
			Sum:       hash,
			Ticket:    c.highwaySession.SigSession,
			Ext:       ext,
		}
		_, e = c.highwaySession.Upload(input)
		if e != nil {
			return nil, errors.Wrap(e, "upload failed")
		}
		break
	}
	if access == nil {
		return nil, errors.New("upload failed, access failed")
	}
	if err != nil {
		return nil, err
	}
	ret := message.NewTechVoiceElement{
		FileUUID: access.MsgInfoBody[0].Index.FileUuid,
		Md5:      hash,
		Sha1:     sha1,
		Size:     length,
		Duration: during,
		NTElem:   access.NtElem,
		//Path:         access.MsgInfoBody[0].Picture.UrlPath,
		//Domain:       access.MsgInfoBody[0].Picture.Domain,
		BusinessType: business,
		SrcUin:       uint64(c.Uin),
	}
	c.voiceUploadCache.Add(cacheKey, ret, time.Hour*12)
	return &ret, nil
}

// UploadLegacyVoice 将语音数据使用群语音通道上传到服务器, 返回 message.NewTechVoiceElement 可直接发送（旧）
func (c *QQClient) UploadLegacyVoice(target message.Source, voice io.ReadSeeker, during int32) (*message.NewTechVoiceElement, error) {
	switch target.SourceType {
	case message.SourceGroup, message.SourcePrivate:
		// ok
	default:
		return nil, errors.New("unsupported source type")
	}

	fh, length := utils.ComputeMd5AndLength(voice)
	_, _ = voice.Seek(0, io.SeekStart)

	key := string(fh)
	pttWaiter.Wait(key)
	defer pttWaiter.Done(key)

	var cmd int32
	var ext []byte
	if target.SourceType == message.SourcePrivate {
		cmd = int32(26)
		ext = c.buildC2CPttStoreBDHExt(target.PrimaryID, fh, int32(length), int32(length))
	} else {
		cmd = int32(29)
		ext = c.buildGroupPttStoreBDHExt(target.PrimaryID, fh, int32(length), 0, int32(length))
	}
	// multi-thread upload is no need
	rsp, err := c.highwaySession.Upload(highway.Transaction{
		CommandID: cmd,
		Body:      voice,
		Sum:       fh,
		Size:      length,
		Ticket:    c.highwaySession.SigSession,
		Ext:       ext,
	})
	if err != nil {
		return nil, err
	}
	if len(rsp) == 0 {
		return nil, errors.New("miss rsp")
	}
	if during == 0 {
		log.Debug("zero voice detected, setting to 8 seconds")
		during = 8
	}
	ptt := &msg.Ptt{
		FileType:  proto.Int32(4),
		SrcUin:    proto.Some(c.Uin),
		FileMd5:   fh,
		FileName:  proto.String(fmt.Sprintf("%x.amr", fh)),
		FileSize:  proto.Int32(int32(length)),
		BoolValid: proto.Bool(true),
		Time:      proto.Some(during),
	}
	if target.SourceType == message.SourceGroup {
		pkt := cmd0x388.D388RspBody{}
		if err = proto.Unmarshal(rsp, &pkt); err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal protobuf message")
		}
		if len(pkt.TryupPttRsp) == 0 {
			return nil, errors.New("miss try up rsp")
		}
		ptt.PbReserve = []byte{8, 0, 40, 0, 56, 0}
		ptt.GroupFileKey = pkt.TryupPttRsp[0].FileKey
		return &message.NewTechVoiceElement{
			SrcUin:      uint64(c.Uin),
			LegacyGroup: &message.GroupVoiceElement{Ptt: ptt},
		}, nil
	} else {
		pkt := cmd0x346.C346RspBody{}
		if err = proto.Unmarshal(rsp, &pkt); err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal protobuf message")
		}
		if pkt.ApplyUploadRsp == nil {
			return nil, errors.New("miss apply upload rsp")
		}
		ptt.FileUuid = pkt.ApplyUploadRsp.Uuid
		ptt.Reserve = c2cPttExtraInfo()
		return &message.NewTechVoiceElement{
			SrcUin:       uint64(c.Uin),
			LegacyFriend: &message.PrivateVoiceElement{Ptt: ptt},
		}, nil
	}
}

// UploadShortVideo 将视频和封面上传到服务器, 返回 message.ShortVideoElement 可直接发送
func (c *QQClient) UploadShortVideo(target message.Source, video, thumb io.ReadSeeker) (*message.ShortVideoElement, error) {
	thumbHash := md5.New()
	thumbLen, _ := io.Copy(thumbHash, thumb)
	thumbSum := thumbHash.Sum(nil)
	videoSum, videoLen := utils.ComputeMd5AndLength(io.TeeReader(video, thumbHash))
	sum := thumbHash.Sum(nil)

	key := string(sum)
	pttWaiter.Wait(key)
	defer pttWaiter.Done(key)

	i, err := c.sendAndWait(c.buildPttGroupShortVideoUploadReqPacket(target, videoSum, thumbSum, videoLen, thumbLen))
	if err != nil {
		return nil, errors.Wrap(err, "upload req error")
	}
	rsp := i.(*pttcenter.ShortVideoUploadRsp)
	videoElement := &message.ShortVideoElement{
		Size:      int32(videoLen),
		ThumbSize: int32(thumbLen),
		Md5:       videoSum,
		ThumbMd5:  thumbSum,
		Guild:     target.SourceType == message.SourceGuildChannel,
	}
	if rsp.FileExists == 1 {
		videoElement.Uuid = []byte(rsp.FileId)
		return videoElement, nil
	}

	var hwRsp []byte
	cmd := int32(25)
	if target.SourceType == message.SourceGuildChannel {
		cmd = 89
	}
	ext, _ := proto.Marshal(c.buildPttShortVideoProto(target, videoSum, thumbSum, videoLen, thumbLen).PttShortVideoUploadReq)
	_, _ = thumb.Seek(0, io.SeekStart)
	_, _ = video.Seek(0, io.SeekStart)
	combined := io.MultiReader(thumb, video)
	input := highway.Transaction{
		CommandID: cmd,
		Body:      combined,
		Size:      videoLen + thumbLen,
		Sum:       sum,
		Ticket:    c.highwaySession.SigSession,
		Ext:       ext,
		Encrypt:   true,
	}
	hwRsp, err = c.highwaySession.Upload(input)
	if err != nil {
		return nil, errors.Wrap(err, "upload video file error")
	}
	if len(hwRsp) == 0 {
		return nil, errors.New("resp is empty")
	}
	rsp = &pttcenter.ShortVideoUploadRsp{}
	if err = proto.Unmarshal(hwRsp, rsp); err != nil {
		return nil, errors.Wrap(err, "decode error")
	}
	videoElement.Uuid = []byte(rsp.FileId)
	return videoElement, nil
}

func (c *QQClient) GetShortVideoUrl(uuid, md5 []byte) string {
	i, err := c.sendAndWait(c.buildPttShortVideoDownReqPacket(uuid, md5))
	if err != nil {
		return ""
	}
	return i.(string)
}

func (c *QQClient) buildGroupPttStoreBDHExt(groupCode int64, md5 []byte, size, codec, voiceLength int32) []byte {
	req := &cmd0x388.D388ReqBody{
		NetType: proto.Uint32(3),
		Subcmd:  proto.Uint32(3),
		TryupPttReq: []*cmd0x388.TryUpPttReq{
			{
				GroupCode:    proto.Uint64(uint64(groupCode)),
				SrcUin:       proto.Uint64(uint64(c.Uin)),
				FileMd5:      md5,
				FileSize:     proto.Uint64(uint64(size)),
				FileName:     md5,
				SrcTerm:      proto.Uint32(5),
				PlatformType: proto.Uint32(9),
				BuType:       proto.Uint32(4),
				InnerIp:      proto.Uint32(0),
				BuildVer:     utils.S2B("6.5.5.663"),
				VoiceLength:  proto.Uint32(uint32(voiceLength)),
				Codec:        proto.Uint32(uint32(codec)),
				VoiceType:    proto.Uint32(1),
				NewUpChan:    proto.Bool(true),
			},
		},
	}
	payload, _ := proto.Marshal(req)
	return payload
}

// PttCenterSvr.ShortVideoDownReq
func (c *QQClient) buildPttShortVideoDownReqPacket(uuid, md5 []byte) (uint16, []byte) {
	seq := c.nextSeq()
	body := &pttcenter.ShortVideoReqBody{
		Cmd: 400,
		Seq: int32(seq),
		PttShortVideoDownloadReq: &pttcenter.ShortVideoDownloadReq{
			FromUin:      c.Uin,
			ToUin:        c.Uin,
			ChatType:     1,
			ClientType:   7,
			FileId:       string(uuid),
			GroupCode:    1,
			FileMd5:      md5,
			BusinessType: 1,
			FileType:     2,
			DownType:     2,
			SceneType:    2,
		},
	}
	payload, _ := proto.Marshal(body)
	packet := c.uniPacketWithSeq(seq, "PttCenterSvr.ShortVideoDownReq", payload)
	return seq, packet
}

func (c *QQClient) buildPttShortVideoProto(target message.Source, videoHash, thumbHash []byte, videoSize, thumbSize int64) *pttcenter.ShortVideoReqBody {
	seq := c.nextSeq()
	chatType := int32(1)
	if target.SourceType == message.SourceGuildChannel {
		chatType = 4
	}
	body := &pttcenter.ShortVideoReqBody{
		Cmd: 300,
		Seq: int32(seq),
		PttShortVideoUploadReq: &pttcenter.ShortVideoUploadReq{
			FromUin:    c.Uin,
			ToUin:      target.PrimaryID,
			ChatType:   chatType,
			ClientType: 2,
			Info: &pttcenter.ShortVideoFileInfo{
				FileName:      fmt.Sprintf("%x.mp4", videoHash),
				FileMd5:       videoHash,
				ThumbFileMd5:  thumbHash,
				FileSize:      videoSize,
				FileResLength: 1280,
				FileResWidth:  720,
				FileFormat:    3,
				FileTime:      120,
				ThumbFileSize: thumbSize,
			},
			GroupCode:        target.PrimaryID,
			SupportLargeSize: 1,
		},
		ExtensionReq: []*pttcenter.ShortVideoExtensionReq{
			{
				SubBusiType: 0,
				UserCnt:     1,
			},
		},
	}
	if target.SourceType == message.SourceGuildChannel {
		body.PttShortVideoUploadReq.BusinessType = 4601
		body.PttShortVideoUploadReq.ToUin = target.SecondaryID
		body.ExtensionReq[0].SubBusiType = 4601
	}
	return body
}

// PttCenterSvr.GroupShortVideoUpReq
func (c *QQClient) buildPttGroupShortVideoUploadReqPacket(target message.Source, videoHash, thumbHash []byte, videoSize, thumbSize int64) (uint16, []byte) {
	pb := c.buildPttShortVideoProto(target, videoHash, thumbHash, videoSize, thumbSize)
	payload, _ := proto.Marshal(pb)
	return c.uniPacket("PttCenterSvr.GroupShortVideoUpReq", payload)
}

// PttCenterSvr.pb_pttCenter_CMD_REQ_APPLY_UPLOAD-500
func (c *QQClient) buildC2CPttStoreBDHExt(target int64, md5 []byte, size, voiceLength int32) []byte {
	seq := c.nextSeq()
	req := &cmd0x346.C346ReqBody{
		Cmd: 500,
		Seq: int32(seq),
		ApplyUploadReq: &cmd0x346.ApplyUploadReq{
			SenderUin:    c.Uin,
			RecverUin:    target,
			FileType:     2,
			FileSize:     int64(size),
			FileName:     hex.EncodeToString(md5),
			Bytes_10MMd5: md5, // 超过10M可能会炸
		},
		BusinessId: 17,
		ClientType: 104,
		ExtensionReq: &cmd0x346.ExtensionReq{
			Id:        3,
			PttFormat: 1,
			NetType:   3,
			VoiceType: 2,
			PttTime:   voiceLength,
		},
	}
	payload, _ := proto.Marshal(req)
	return payload
}

// PttCenterSvr.ShortVideoDownReq
func decodePttShortVideoDownResponse(_ *QQClient, pkt *network.Packet) (any, error) {
	rsp := pttcenter.ShortVideoRspBody{}
	if err := proto.Unmarshal(pkt.Payload, &rsp); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal protobuf message")
	}
	if rsp.PttShortVideoDownloadRsp == nil || rsp.PttShortVideoDownloadRsp.DownloadAddr == nil {
		return nil, errors.New("resp error")
	}
	return rsp.PttShortVideoDownloadRsp.DownloadAddr.Host[0] + rsp.PttShortVideoDownloadRsp.DownloadAddr.UrlArgs, nil
}

// PttCenterSvr.GroupShortVideoUpReq
func decodeGroupShortVideoUploadResponse(_ *QQClient, pkt *network.Packet) (any, error) {
	rsp := pttcenter.ShortVideoRspBody{}
	if err := proto.Unmarshal(pkt.Payload, &rsp); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal protobuf message")
	}
	if rsp.PttShortVideoUploadRsp == nil {
		return nil, errors.New("resp error")
	}
	if rsp.PttShortVideoUploadRsp.RetCode != 0 {
		return nil, errors.Errorf("ret code error: %v", rsp.PttShortVideoUploadRsp.RetCode)
	}
	return rsp.PttShortVideoUploadRsp, nil
}
