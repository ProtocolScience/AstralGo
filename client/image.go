package client

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/ProtocolScience/AstralGo/binary"
	"github.com/ProtocolScience/AstralGo/client/internal/highway"
	"github.com/ProtocolScience/AstralGo/client/internal/network"
	"github.com/ProtocolScience/AstralGo/client/nt"
	"github.com/ProtocolScience/AstralGo/client/pb/cmd0x388"
	"github.com/ProtocolScience/AstralGo/client/pb/database"
	highway2 "github.com/ProtocolScience/AstralGo/client/pb/highway"
	"github.com/ProtocolScience/AstralGo/client/pb/oidb"
	"github.com/ProtocolScience/AstralGo/internal/proto"
	"github.com/ProtocolScience/AstralGo/message"
	"github.com/ProtocolScience/AstralGo/utils"
	"github.com/fumiama/imgsz"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"io"
	"strings"
	"time"
)

func init() {
	decoders["ImgStore.GroupPicUp"] = decodeGroupImageStoreResponse
	decoders["ImgStore.GroupPicDown"] = decodeGroupImageDownloadResponse
	decoders["OidbSvc.0xe07_0"] = decodeImageOcrResponse
}

var imgWaiter = utils.NewUploadWaiter()

type imageUploadResponse struct {
	UploadKey     []byte
	UploadIp      []uint32
	UploadPort    []uint32
	Width         int32
	Height        int32
	Message       string
	DownloadIndex string
	ResourceId    string
	FileId        int64
	ResultCode    int32
	IsExists      bool
}

func ImageExt2Type(ext string) uint32 {
	//TODO 1001,2001=png 1000=jpg 2000,3,4=gif 1005=bmp 1002=webp 2001=png
	ext = strings.ToLower(ext)
	mapping := map[string]uint32{
		"png":  1001,
		"jpg":  1000,
		"jpeg": 1000,
		"gif":  2000,
		"bmp":  1005,
		"webp": 1002,
	}

	if code, exists := mapping[ext]; exists {
		return code
	}
	log.Warnf("couldn't parse file ext : %s", ext)
	// Return a default value or an error code if the extension is not found
	return 0
}
func (c *QQClient) UploadImage(target message.Source, img io.ReadSeeker) (message.IMessageElement, error) {
	switch target.SourceType {
	case message.SourceGuildChannel, message.SourceGuildDirect:
		return c.uploadGuildImage(target, img)
	case message.SourcePrivate, message.SourceGroup:
		return c.uploadNewTechImage(target, img)
	default:
		return nil, errors.New("unsupported target type")
	}
}

func (c *QQClient) UploadLegacyImage(target message.Source, img io.ReadSeeker) (message.IMessageElement, error) {
	_, _ = img.Seek(0, io.SeekStart) // safe
	fh, length := utils.ComputeMd5AndLength(img)
	_, _ = img.Seek(0, io.SeekStart)

	key := string(fh)
	imgWaiter.Wait(key)
	defer imgWaiter.Done(key)

	var r any
	var err error
	var cmd int32
	var input highway.Transaction
	switch target.SourceType {
	case message.SourceGroup:
		r, err = c.sendAndWait(c.buildGroupImageStorePacket(target.PrimaryID, fh, int32(length)))
		cmd = 2
	case message.SourcePrivate:
		r, err = c.sendAndWait(c.buildOffPicUpPacket(target.PrimaryID, fh, int32(length)))
		cmd = 1
	default:
		return nil, errors.Errorf("unsupported target type %v", target.SourceType)
	}
	rsp := r.(*imageUploadResponse)
	if rsp.ResultCode != 0 {
		return nil, errors.New(rsp.Message)
	}
	if rsp.IsExists {
		goto ok
	}
	if c.highwaySession.AddrLength() == 0 {
		for i, addr := range rsp.UploadIp {
			c.highwaySession.AppendAddr(addr, rsp.UploadPort[i])
		}
	}
	input = highway.Transaction{
		CommandID: cmd,
		Body:      img,
		Size:      length,
		Sum:       fh,
		Ticket:    rsp.UploadKey,
	}
	_, err = c.highwaySession.Upload(input)
	if err != nil {
		return nil, errors.Wrap(err, "upload failed")
	}
ok:
	_, _ = img.Seek(0, io.SeekStart)
	i, t, _ := imgsz.DecodeSize(img)
	imageType := ImageExt2Type(t)
	width := int32(i.Width)
	height := int32(i.Height)
	url := "https://c2cpicdw.qpic.cn/offpic_new/0" + rsp.ResourceId + "/0?term=2"
	if target.SourceType == message.SourceGroup {
		return &message.GroupImageElement{
			ImageId:   rsp.ResourceId,
			Md5:       fh,
			FileId:    rsp.FileId,
			Size:      int32(length),
			Width:     width,
			Height:    height,
			ImageType: int32(imageType),
			Url:       url,
		}, nil
	} else {
		return &message.FriendImageElement{
			ImageId: rsp.ResourceId,
			Md5:     fh,
			Size:    int32(length),
			Width:   width,
			Height:  height,
			Url:     url,
		}, nil
	}
}

func (c *QQClient) uploadNewTechImage(target message.Source, img io.ReadSeeker) (message.IMessageElement, error) {
	_, _ = img.Seek(0, io.SeekStart)
	md5, sha1, length, err := utils.ComputeMd5Sha1AndLength(img)
	if err != nil {
		return nil, err
	}
	_, _ = img.Seek(0, io.SeekStart)
	i, ext, err := imgsz.DecodeSize(img)
	if err != nil {
		return nil, err
	}
	_, _ = img.Seek(0, io.SeekStart)
	width := uint32(i.Width)
	height := uint32(i.Height)
	image := nt.ImageParam{
		Width:       width,
		Height:      height,
		SubFileType: 0,
		Type:        ImageExt2Type(ext),
		MD5:         md5,
		SHA1:        sha1,
		Size:        int64(length),
		Filename:    strings.ToUpper(hex.EncodeToString(md5)) + ".png",
	}
	media := nt.MediaParam{
		Type:   nt.IMAGE,
		Params: []nt.DataParam{image},
	}
	var resp interface{}
	var commandId int32
	var business uint32
	switch target.SourceType {
	case message.SourceGroup:
		commandId = 1004
		business = nt.BusinessGroupImage
		resp, err = c.sendAndWait(c.buildNewTechCommonGroupImageUpPacket(&media, target.PrimaryID))
		if err != nil {
			return nil, err
		}
	case message.SourcePrivate:
		commandId = 1003
		business = nt.BusinessFriendImage
		resp, err = c.sendAndWait(c.buildNewTechCommonFriendImageUpPacket(&media, target.PrimaryID))
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
		ext, err := resp.(nt.RequireUpload).RichMediaHighwayExt(img, length, 0)
		_, _ = img.Seek(0, io.SeekStart)
		input := highway.Transaction{
			CommandID: commandId,
			Body:      img,
			Size:      int64(length),
			Sum:       md5,
			Ticket:    c.highwaySession.SigSession,
			Ext:       ext,
		}
		_, err = c.highwaySession.Upload(input)
		if err != nil {
			return nil, errors.Wrap(err, "upload failed")
		}
		break
	}
	if access == nil {
		return nil, errors.New("upload failed, access failed")
	}
	if err != nil {
		return nil, err
	}
	return &message.NewTechImageElement{
		FileUUID:     access.MsgInfoBody[0].Index.FileUuid,
		Md5:          md5,
		Sha1:         sha1,
		Size:         length,
		Width:        width,
		Height:       height,
		Path:         access.MsgInfoBody[0].Picture.UrlPath,
		Domain:       access.MsgInfoBody[0].Picture.Domain,
		BusinessType: business,
		ImageType:    access.MsgInfoBody[0].Index.Info.Type.PicFormat,
	}, nil
}

func (c *QQClient) uploadGuildImage(target message.Source, img io.ReadSeeker) (*message.NewTechImageElement, error) {
	_, _ = img.Seek(0, io.SeekStart) // safe
	fh, length := utils.ComputeMd5AndLength(img)
	_, _ = img.Seek(0, io.SeekStart)

	key := string(fh)
	imgWaiter.Wait(key)
	defer imgWaiter.Done(key)

	cmd := int32(83)
	ext := proto.DynamicMessage{
		11: target.PrimaryID,
		12: target.SecondaryID,
	}.Encode()

	var r any
	var err error
	var input highway.Transaction
	switch target.SourceType {
	case message.SourceGuildChannel, message.SourceGuildDirect:
		r, err = c.sendAndWait(c.buildGuildImageStorePacket(uint64(target.PrimaryID), uint64(target.SecondaryID), fh, uint64(length)))
	default:
		return nil, errors.Errorf("unsupported target type %v", target.SourceType)
	}
	if err != nil {
		return nil, err
	}
	rsp := r.(*imageUploadResponse)
	if rsp.ResultCode != 0 {
		return nil, errors.New(rsp.Message)
	}
	if rsp.IsExists {
		goto ok
	}
	if c.highwaySession.AddrLength() == 0 {
		for i, addr := range rsp.UploadIp {
			c.highwaySession.AppendAddr(addr, rsp.UploadPort[i])
		}
	}

	input = highway.Transaction{
		CommandID: cmd,
		Body:      img,
		Size:      length,
		Sum:       fh,
		Ticket:    rsp.UploadKey,
		Ext:       ext,
	}
	_, err = c.highwaySession.Upload(input)
	if err != nil {
		return nil, errors.Wrap(err, "upload failed")
	}
ok:
	_, _ = img.Seek(0, io.SeekStart)
	i, t, _ := imgsz.DecodeSize(img)
	width := int32(i.Width)
	height := int32(i.Height)
	if target.SourceType != message.SourceGroup {
		c.warning("warning: decode image error: %v. this image will be displayed by wrong size in pc guild client", err)
		width = 200
		height = 200
	}
	return &message.NewTechImageElement{
		LegacyGuild: &message.GuildImageElement{
			FileId:        rsp.FileId,
			FilePath:      fmt.Sprintf("%x.jpg", fh),
			Size:          int32(length),
			DownloadIndex: rsp.DownloadIndex,
			Width:         width,
			Height:        height,
			ImageType:     int32(ImageExt2Type(t)),
			Md5:           fh,
		},
	}, nil
}

// ImgStore.GroupPicUp
func (c *QQClient) buildGroupImageStorePacket(groupCode int64, md5 []byte, size int32) (uint16, []byte) {
	name := utils.RandomString(16) + ".gif"
	req := &cmd0x388.D388ReqBody{
		NetType: proto.Uint32(3),
		Subcmd:  proto.Uint32(1),
		TryupImgReq: []*cmd0x388.TryUpImgReq{
			{
				GroupCode:    proto.Uint64(uint64(groupCode)),
				SrcUin:       proto.Uint64(uint64(c.Uin)),
				FileMd5:      md5,
				FileSize:     proto.Uint64(uint64(size)),
				FileName:     utils.S2B(name),
				SrcTerm:      proto.Uint32(5),
				PlatformType: proto.Uint32(9),
				BuType:       proto.Uint32(1),
				PicType:      proto.Uint32(1000),
				BuildVer:     utils.S2B("8.2.7.4410"),
				AppPicType:   proto.Uint32(1006),
				FileIndex:    EmptyBytes,
				TransferUrl:  EmptyBytes,
			},
		},
		Extension: EmptyBytes,
	}
	payload, _ := proto.Marshal(req)
	return c.uniPacket("ImgStore.GroupPicUp", payload)
}
func (c *QQClient) buildGroupImageDownloadPacket(fileId, groupCode int64, fileMd5 []byte) (uint16, []byte) {
	req := &cmd0x388.D388ReqBody{
		NetType: proto.Uint32(3),
		Subcmd:  proto.Uint32(2),
		GetimgUrlReq: []*cmd0x388.GetImgUrlReq{
			{
				FileId:          proto.Uint64(0), // index
				DstUin:          proto.Uint64(uint64(c.Uin)),
				GroupCode:       proto.Uint64(uint64(groupCode)),
				FileMd5:         fileMd5,
				PicUpTimestamp:  proto.Uint32(uint32(time.Now().Unix())),
				Fileid:          proto.Uint64(uint64(fileId)),
				UrlFlag:         proto.Uint32(8),
				UrlType:         proto.Uint32(3),
				ReqPlatformType: proto.Uint32(9),
				ReqTerm:         proto.Uint32(5),
				InnerIp:         proto.Uint32(0),
			},
		},
	}
	payload, _ := proto.Marshal(req)
	return c.uniPacket("ImgStore.GroupPicDown", payload)
}

func (c *QQClient) GetGroupImageDownloadUrl(fileId, groupCode int64, fileMd5 []byte) (string, error) {
	i, err := c.sendAndWait(c.buildGroupImageDownloadPacket(fileId, groupCode, fileMd5))
	if err != nil {
		return "", err
	}
	return i.(string), nil
}

func (c *QQClient) QueryFriendImage(target int64, hash []byte, size int32) (*message.NewTechImageElement, error) {
	i, err := c.sendAndWait(c.buildOffPicUpPacket(target, hash, size))
	if err != nil {
		return nil, err
	}
	rsp := i.(*imageUploadResponse)
	if rsp.ResultCode != 0 {
		return nil, errors.New(rsp.Message)
	}
	if !rsp.IsExists {
		return &message.NewTechImageElement{
			Md5:    hash,
			Size:   uint32(size),
			Path:   "/offpic_new/0" + rsp.ResourceId + "/0?term=2",
			Domain: "c2cpicdw.qpic.cn",
		}, errors.WithStack(ErrNotExists)
	}
	return &message.NewTechImageElement{
		Md5:    hash,
		Path:   "/offpic_new/0" + rsp.ResourceId + "/0?term=2",
		Domain: "c2cpicdw.qpic.cn",
		Size:   uint32(size),
		Height: uint32(rsp.Height),
		Width:  uint32(rsp.Width),
	}, nil
}

func (c *QQClient) ImageOcr(img any) (*OcrResponse, error) {
	url := ""
	switch e := img.(type) {
	case *message.NewTechImageElement:
		url = c.GetElementImageUrl(e)
		if b, err := utils.HTTPGetReadCloser(url, ""); err == nil {
			if url, err = c.uploadOcrImage(b, int32(e.Size), e.Md5); err != nil {
				url = e.Path
			}
			_ = b.Close()
		}
		rsp, err := c.sendAndWait(c.buildImageOcrRequestPacket(url, fmt.Sprintf("%X", e.Md5), int32(e.Size), int32(e.Width), int32(e.Height)))
		if err != nil {
			return nil, err
		}
		return rsp.(*OcrResponse), nil
	}
	return nil, errors.New("image error")
}

func (c *QQClient) QueryImage(groupCode int64, friendUin int64, data *database.DatabaseImage) (*message.NewTechImageElement, error) {
	if len(data.Sha1) == 0 { //NT协议要求必须要有SHA1，为了从URL获得SHA1，有且只能下载
		return nil, errors.New("image file cannot query with sha1 because it is not NewTechImageElement")
	}
	image := nt.ImageParam{
		Type:        data.ImageType,
		MD5:         data.Md5,
		SHA1:        data.Sha1,
		Size:        int64(data.Size),
		Filename:    strings.ToUpper(hex.EncodeToString(data.Md5)) + ".png",
		Width:       data.Width,
		Height:      data.Height,
		SubFileType: 0,
	}
	media := nt.MediaParam{
		Type:   nt.IMAGE,
		Params: []nt.DataParam{image},
	}
	var err error
	var resp interface{}
	var business uint32
	if groupCode == 0 {
		business = nt.BusinessFriendImage
		resp, err = c.sendAndWait(c.buildNewTechCommonFriendImageUpPacket(&media, friendUin))
	} else {
		business = nt.BusinessGroupImage
		resp, err = c.sendAndWait(c.buildNewTechCommonGroupImageUpPacket(&media, groupCode))
	}
	if err != nil {
		return nil, err
	}
	switch resp.(type) {
	case nt.FileExists:
		r := resp.(nt.FileExists)
		access := &r.UploadAccess
		if access == nil {
			return nil, errors.New("access failed")
		}
		return &message.NewTechImageElement{
			FileUUID:     access.MsgInfoBody[0].Index.FileUuid,
			Md5:          data.Md5,
			Sha1:         data.Sha1,
			Size:         data.Size,
			Width:        access.MsgInfoBody[0].Index.Info.Width,
			Height:       access.MsgInfoBody[0].Index.Info.Height,
			Path:         access.MsgInfoBody[0].Picture.UrlPath,
			Domain:       access.MsgInfoBody[0].Picture.Domain,
			BusinessType: business,
		}, nil
	default:
		return nil, errors.New("image does not exist")
	}
}

func (c *QQClient) uploadOcrImage(img io.Reader, size int32, sum []byte) (string, error) {
	r := make([]byte, 16)
	rand.Read(r)
	ext, _ := proto.Marshal(&highway2.CommFileExtReq{
		ActionType: proto.Uint32(0),
		Uuid:       binary.GenUUID(r),
	})

	rsp, err := c.highwaySession.Upload(highway.Transaction{
		CommandID: 76,
		Body:      img,
		Size:      int64(size),
		Sum:       sum,
		Ticket:    c.highwaySession.SigSession,
		Ext:       ext,
	})
	if err != nil {
		return "", errors.Wrap(err, "upload ocr image error")
	}
	rspExt := highway2.CommFileExtRsp{}
	if err = proto.Unmarshal(rsp, &rspExt); err != nil {
		return "", errors.Wrap(err, "error unmarshal highway resp")
	}
	return string(rspExt.DownloadUrl), nil
}

// OidbSvc.0xe07_0
func (c *QQClient) buildImageOcrRequestPacket(url, md5 string, size, weight, height int32) (uint16, []byte) {
	body := &oidb.DE07ReqBody{
		Version:  1,
		Entrance: 3,
		OcrReqBody: &oidb.OCRReqBody{
			ImageUrl:              url,
			OriginMd5:             md5,
			AfterCompressMd5:      md5,
			AfterCompressFileSize: size,
			AfterCompressWeight:   weight,
			AfterCompressHeight:   height,
			IsCut:                 false,
		},
	}
	b, _ := proto.Marshal(body)
	payload := c.packOIDBPackage(3591, 0, b)
	return c.uniPacket("OidbSvc.0xe07_0", payload)
}

// ImgStore.GroupPicUp
func decodeGroupImageStoreResponse(_ *QQClient, packet *network.Packet) (any, error) {
	pkt := cmd0x388.D388RspBody{}
	err := proto.Unmarshal(packet.Payload, &pkt)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal protobuf message")
	}
	rsp := pkt.TryupImgRsp[0]
	if rsp.Result.Unwrap() != 0 {
		return &imageUploadResponse{
			ResultCode: int32(rsp.Result.Unwrap()),
			Message:    utils.B2S(rsp.FailMsg),
		}, nil
	}
	if rsp.FileExit.Unwrap() {
		if rsp.ImgInfo != nil {
			return &imageUploadResponse{IsExists: true, FileId: int64(rsp.Fileid.Unwrap()), Width: int32(rsp.ImgInfo.FileWidth.Unwrap()), Height: int32(rsp.ImgInfo.FileHeight.Unwrap())}, nil
		}
		return &imageUploadResponse{IsExists: true, FileId: int64(rsp.Fileid.Unwrap())}, nil
	}
	return &imageUploadResponse{
		FileId:     int64(rsp.Fileid.Unwrap()),
		UploadKey:  rsp.UpUkey,
		UploadIp:   rsp.UpIp,
		UploadPort: rsp.UpPort,
	}, nil
}

func decodeGroupImageDownloadResponse(_ *QQClient, pkt *network.Packet) (any, error) {
	rsp := cmd0x388.D388RspBody{}
	if err := proto.Unmarshal(pkt.Payload, &rsp); err != nil {
		return nil, errors.Wrap(err, "unmarshal protobuf message error")
	}
	if len(rsp.GetimgUrlRsp) == 0 {
		return nil, errors.New("response not found")
	}
	if len(rsp.GetimgUrlRsp[0].FailMsg) != 0 {
		return nil, errors.New(utils.B2S(rsp.GetimgUrlRsp[0].FailMsg))
	}
	return fmt.Sprintf("https://%s%s", rsp.GetimgUrlRsp[0].DownDomain, rsp.GetimgUrlRsp[0].BigDownPara), nil
}

// OidbSvc.0xe07_0
func decodeImageOcrResponse(_ *QQClient, pkt *network.Packet) (any, error) {
	rsp := oidb.DE07RspBody{}
	err := unpackOIDBPackage(pkt.Payload, &rsp)
	if err != nil {
		return nil, err
	}
	if rsp.Wording != "" {
		if strings.Contains(rsp.Wording, "服务忙") {
			return nil, errors.New("未识别到文本")
		}
		return nil, errors.New(rsp.Wording)
	}
	if rsp.RetCode != 0 {
		return nil, errors.Errorf("server error, code: %v msg: %v", rsp.RetCode, rsp.ErrMsg)
	}
	texts := make([]*TextDetection, 0, len(rsp.OcrRspBody.TextDetections))
	for _, text := range rsp.OcrRspBody.TextDetections {
		points := make([]*Coordinate, 0, len(text.Polygon.Coordinates))
		for _, c := range text.Polygon.Coordinates {
			points = append(points, &Coordinate{
				X: c.X,
				Y: c.Y,
			})
		}
		texts = append(texts, &TextDetection{
			Text:        text.DetectedText,
			Confidence:  text.Confidence,
			Coordinates: points,
		})
	}
	return &OcrResponse{
		Texts:    texts,
		Language: rsp.OcrRspBody.Language,
	}, nil
}
