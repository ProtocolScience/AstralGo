package message

import (
	"encoding/hex"
	"fmt"
	"github.com/ProtocolScience/AstralGo/client/nt"
	"github.com/ProtocolScience/AstralGo/client/pb/msg"
	"github.com/ProtocolScience/AstralGo/client/pb/nt/media"
	"github.com/ProtocolScience/AstralGo/internal/proto"
	"strings"
)

/* -------- Definitions -------- */

type NTImageElement struct {
	FileUUID     string
	Size         uint32
	Width        uint32
	Height       uint32
	Md5          []byte
	Sha1         []byte
	Url          string
	Domain       string
	BusinessType uint32
	//data     []byte
}

type GroupImageElement struct {
	ImageId      string
	FileId       int64
	ImageType    int32
	ImageBizType ImageBizType
	Size         int32
	Width        int32
	Height       int32
	Md5          []byte
	Url          string

	// EffectID show pic effect id.
	EffectID int32
	Flash    bool
}

type FriendImageElement struct {
	ImageId string
	Md5     []byte
	Size    int32
	Width   int32
	Height  int32
	Url     string

	Flash bool
}

type GuildImageElement struct {
	FileId        int64
	FilePath      string
	ImageType     int32
	Size          int32
	Width         int32
	Height        int32
	DownloadIndex string
	Md5           []byte
	Url           string
}

type ImageBizType uint32

const (
	UnknownBizType  ImageBizType = 0
	CustomFaceImage ImageBizType = 1
	HotImage        ImageBizType = 2
	DouImage        ImageBizType = 3 // 斗图
	ZhiTuImage      ImageBizType = 4
	StickerImage    ImageBizType = 7
	SelfieImage     ImageBizType = 8
	StickerAdImage  ImageBizType = 9
	RelatedEmoImage ImageBizType = 10
	HotSearchImage  ImageBizType = 13
)

/* ------ Implementations ------ */

func NewGroupImage(id string, md5 []byte, fid int64, size, width, height, imageType int32) *GroupImageElement {
	return &GroupImageElement{
		ImageId:   id,
		FileId:    fid,
		Md5:       md5,
		Size:      size,
		ImageType: imageType,
		Width:     width,
		Height:    height,
		Url:       fmt.Sprintf("https://gchat.qpic.cn/gchatpic_new/1/0-0-%X/0?term=2", md5),
	}
}

func (n *NTImageElement) Type() ElementType {
	return Image
}

func (e *GroupImageElement) Type() ElementType {
	return Image
}

func (e *FriendImageElement) Type() ElementType {
	return Image
}

func (e *GuildImageElement) Type() ElementType {
	return Image
}

func (e *NTImageElement) Pack() (r []*msg.Elem) {
	//[2025-01-04 04:22:03] [WARNING]: FILE UUID: EhTyQTXeR021iPx-EcuGUQl_29ES9Bit3AYg_woo4uKjwrDaigMyBHByb2RQgL2jAVoQhbM3xrpmpRjb-qCkJ6aZeg
	//[2025-01-04 04:22:03] [WARNING]: FILE MD5: d41d8cd98f00b204e9800998ecf8427e
	//[2025-01-04 04:22:03] [WARNING]: FILE SHA1: f24135de474db588fc7e11cb8651097fdbd112f4
	//[2025-01-04 04:22:03] [WARNING]: PACK NT IMAGE:0abd030aef010a830108addc06122064343164386364393866303062323034653938303039393865636638343237651a2866323431333564653437346462353838666337653131636238363531303937666462643131326634222444343144384344393846303042323034453938303039393845434638343237452e706e672a05080110e90730b808388408125a4568547951545865523032316950782d4563754755516c5f3239455339426974334159675f776f6f34754b6a7772446169674d794248427962325251674c326a41566f5168624d337872706d70526a622d71436b4a36615a6567180120ed8de1bb062880bda30112b2010a762f646f776e6c6f61643f61707069643d313430372666696c6569643d4568547951545865523032316950782d4563754755516c5f3239455339426974334159675f776f6f34754b6a7772446169674d794248427962325251674c326a41566f5168624d337872706d70526a622d71436b4a36615a6567121f0a0726737065633d30120926737065633d3732301a0926737065633d3139381a176d756c74696d656469612e6e742e71712e636f6d2e636e28013212a80602b00601c00c02d20c0608a98bfe830312360a305a210800180020004200500062009201009a0100a2010c080012001800200028003a00c83e02d03e02d83e83dace960712001a00

	//isGroup := false // Replace with actual check
	hash := hex.EncodeToString(e.Md5)
	msgInfoBody := []*media.MsgInfoBody{
		{
			Index: &media.IndexNode{
				Info: &media.FileInfo{
					FileSize: e.Size,
					FileHash: hash,
					FileSha1: hex.EncodeToString(e.Sha1),
					FileName: strings.ToUpper(hash) + ".png",
					Type: &media.FileType{
						Type:      1,
						PicFormat: 1001,
					},
					Width:    e.Width,
					Height:   e.Height,
					Original: 0,
				},
				FileUuid: e.FileUUID,
				StoreId:  1,
			},
			Picture: &media.PictureInfo{
				UrlPath: e.Url,
				Domain:  e.Domain,
				Ext: &media.PicUrlExtInfo{
					OriginalParameter: "&spec=0",
					BigParameter:      "&spec=720",
					ThumbParameter:    "&spec=198",
				},
			},
		},
	}
	msgInfo := media.MsgInfo{
		MsgInfoBody: msgInfoBody,
		ExtBizInfo:  &media.ExtBizInfo{},
	}
	pbElem, _ := proto.Marshal(&msgInfo)
	commonElem := msg.CommonElem{
		ServiceType:  proto.Int32(48),
		PbElem:       pbElem,
		BusinessType: proto.Int32(nt.BusinessGroupImage),
	}
	elem := &msg.Elem{CommonElem: &commonElem}
	return []*msg.Elem{elem}
}

func (e *GroupImageElement) Pack() (r []*msg.Elem) {
	// width and height are required, set 720*480 if not set
	if e.Width == 0 {
		e.Width = 720
	}
	if e.Height == 0 {
		e.Height = 480
	}

	cface := &msg.CustomFace{
		FileType: proto.Int32(66),
		Useful:   proto.Int32(1),
		// Origin:    1,
		BizType:   proto.Int32(5),
		Width:     proto.Some(e.Width),
		Height:    proto.Some(e.Height),
		FileId:    proto.Int32(int32(e.FileId)),
		FilePath:  proto.Some(e.ImageId),
		ImageType: proto.Some(e.ImageType),
		Size:      proto.Some(e.Size),
		Md5:       e.Md5,
		Flag:      make([]byte, 4),
		// OldData:  imgOld,
	}

	if e.Flash { // resolve flash pic
		flash := &msg.MsgElemInfoServtype3{FlashTroopPic: cface}
		data, _ := proto.Marshal(flash)
		flashElem := &msg.Elem{
			CommonElem: &msg.CommonElem{
				ServiceType: proto.Int32(3),
				PbElem:      data,
			},
		}
		textHint := &msg.Elem{
			Text: &msg.Text{
				Str: proto.String("[闪照]请使用新版手机QQ查看闪照。"),
			},
		}
		return []*msg.Elem{flashElem, textHint}
	}
	res := &msg.ResvAttr{}
	if e.EffectID != 0 { // resolve show pic
		res.ImageShow = &msg.AnimationImageShow{
			EffectId:       proto.Some(e.EffectID),
			AnimationParam: []byte("{}"),
		}
		cface.Flag = []byte{0x11, 0x00, 0x00, 0x00}
	}
	if e.ImageBizType != UnknownBizType {
		res.ImageBizType = proto.Uint32(uint32(e.ImageBizType))
	}
	cface.PbReserve, _ = proto.Marshal(res)
	elem := &msg.Elem{CustomFace: cface}
	return []*msg.Elem{elem}
}

func (e *FriendImageElement) Pack() []*msg.Elem {
	image := &msg.NotOnlineImage{
		FilePath:     proto.Some(e.ImageId),
		ResId:        proto.Some(e.ImageId),
		OldPicMd5:    proto.Some(false),
		PicMd5:       e.Md5,
		PicHeight:    proto.Some(e.Height),
		PicWidth:     proto.Some(e.Width),
		DownloadPath: proto.Some(e.ImageId),
		Original:     proto.Int32(1),
	}

	if e.Flash {
		flash := &msg.MsgElemInfoServtype3{FlashC2CPic: image}
		data, _ := proto.Marshal(flash)
		flashElem := &msg.Elem{
			CommonElem: &msg.CommonElem{
				ServiceType: proto.Int32(3),
				PbElem:      data,
			},
		}
		textHint := &msg.Elem{
			Text: &msg.Text{
				Str: proto.String("[闪照]请使用新版手机QQ查看闪照。"),
			},
		}
		return []*msg.Elem{flashElem, textHint}
	}

	elem := &msg.Elem{NotOnlineImage: image}
	return []*msg.Elem{elem}
}

func (e *GuildImageElement) Pack() (r []*msg.Elem) {
	cface := &msg.CustomFace{
		FileType:  proto.Int32(66),
		Useful:    proto.Int32(1),
		BizType:   proto.Int32(0),
		Width:     proto.Some(e.Width),
		Height:    proto.Some(e.Height),
		FileId:    proto.Int32(int32(e.FileId)),
		FilePath:  proto.Some(e.FilePath),
		ImageType: proto.Some(e.ImageType),
		Size:      proto.Some(e.Size),
		Md5:       e.Md5,
		PbReserve: proto.DynamicMessage{
			1: 0, 2: 0, 6: "", 10: 0, 15: 8,
			20: e.DownloadIndex,
		}.Encode(),
	}
	elem := &msg.Elem{CustomFace: cface}
	return []*msg.Elem{elem}
}
