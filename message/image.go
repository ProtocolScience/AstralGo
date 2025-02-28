package message

import (
	"github.com/ProtocolScience/AstralGo/client/pb/msg"
	"github.com/ProtocolScience/AstralGo/internal/proto"
)

/* -------- Definitions -------- */

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
	//Flash    bool 群闪照已下线
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

func (e *GroupImageElement) Type() ElementType {
	return Image
}

func (e *FriendImageElement) Type() ElementType {
	return Image
}

func (e *GuildImageElement) Type() ElementType {
	return Image
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
