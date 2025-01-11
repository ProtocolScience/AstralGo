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

type NewTechImageElement struct {
	FileUUID     string
	Size         uint32
	Width        uint32
	Height       uint32
	Md5          []byte
	Sha1         []byte
	Path         string
	Url          string
	Domain       string
	BusinessType uint32
	ImageType    uint32 //1001,2001=png 1000=jpg 2000,3,4=gif 1005=bmp 1002=webp 2001=png

	LegacyGroup  *GroupImageElement
	LegacyGuild  *GuildImageElement
	LegacyFriend *FriendImageElement
}

func (e *NewTechImageElement) GetLegacyOrSelf() IMessageElement {
	if e.LegacyGuild != nil {
		return e.LegacyGuild
	} else if e.LegacyGroup != nil {
		return e.LegacyGroup
	} else if e.LegacyFriend != nil {
		return e.LegacyFriend
	}
	return e
}
func (e *NewTechImageElement) DownloadUrl() string {
	return fmt.Sprintf("https://%s%s&spec=0",
		e.Domain,
		e.Path,
	)
}
func (e *NewTechImageElement) IsOldGroupImage() bool {
	return e.LegacyGroup != nil
}

func (e *NewTechImageElement) Type() ElementType {
	return Image
}

func (e *NewTechImageElement) Pack() (r []*msg.Elem) {
	if e.LegacyGuild != nil {
		return e.LegacyGuild.Pack()
	} else if e.LegacyGroup != nil {
		return e.LegacyGroup.Pack()
	} else if e.LegacyFriend != nil {
		return e.LegacyFriend.Pack()
	} else {
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
							PicFormat: e.ImageType,
						},
						Width:    e.Width,
						Height:   e.Height,
						Original: 0,
					},
					FileUuid: e.FileUUID,
					StoreId:  1,
				},
				Picture: &media.PictureInfo{
					UrlPath: e.Path,
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
}
