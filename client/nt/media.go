package nt

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ProtocolScience/AstralGo/binary/sha1Plus"
	"github.com/ProtocolScience/AstralGo/client/pb/nt/highway"
	"github.com/ProtocolScience/AstralGo/client/pb/nt/media"
	"github.com/ProtocolScience/AstralGo/internal/proto"
	"io"
	"strconv"
)

type MediaParamType int

const (
	AUDIO MediaParamType = iota
	IMAGE
	VIDEO
)

type DataParam interface {
	GetType() uint32
	GetMD5() string
	GetSHA1() string
	GetSize() int64
	GetFilename() string
	GetSubFileType() uint32
}

type MediaParam struct {
	Type   MediaParamType
	Params []DataParam
}

type ImageParam struct {
	Width       uint32
	Height      uint32
	SubFileType uint32
	Type        uint32
	MD5         []byte
	SHA1        []byte
	Size        int64
	Filename    string
}

func (i ImageParam) GetType() uint32 {
	return i.Type
}

func (i ImageParam) GetMD5() string {
	return hex.EncodeToString(i.MD5)
}

func (i ImageParam) GetSHA1() string {
	return hex.EncodeToString(i.SHA1)
}

func (i ImageParam) GetSize() int64 {
	return i.Size
}

func (i ImageParam) GetFilename() string {
	return i.Filename
}

func (i ImageParam) GetSubFileType() uint32 {
	return i.SubFileType
}

type AudioParam struct {
	RecordTime  uint32
	SubFileType uint32
	Type        uint32
	MD5         []byte
	SHA1        []byte
	Size        int64
	Filename    string
}

func (a AudioParam) GetType() uint32 {
	return a.Type
}

func (a AudioParam) GetMD5() string {
	return hex.EncodeToString(a.MD5)
}

func (a AudioParam) GetSHA1() string {
	return hex.EncodeToString(a.SHA1)
}

func (a AudioParam) GetSize() int64 {
	return a.Size
}

func (a AudioParam) GetFilename() string {
	return a.Filename
}

func (a AudioParam) GetSubFileType() uint32 {
	return a.SubFileType
}

type VideoParam struct {
	PlayTime    uint32
	SubFileType uint32
	Type        uint32
	MD5         []byte
	SHA1        []byte
	Size        int64
	Filename    string
}

func (v VideoParam) GetType() uint32 {
	return v.Type
}

func (v VideoParam) GetMD5() string {
	return hex.EncodeToString(v.MD5)
}

func (v VideoParam) GetSHA1() string {
	return hex.EncodeToString(v.SHA1)
}

func (v VideoParam) GetSize() int64 {
	return v.Size
}

func (v VideoParam) GetFilename() string {
	return v.Filename
}

func (v VideoParam) GetSubFileType() uint32 {
	return v.SubFileType
}
func PictureDefault() media.ExtBizInfo {
	return media.ExtBizInfo{
		Pic: &media.PicExtBizInfo{
			BytesPbReserveC2C: []byte{
				0x08, 0x00, 0x18, 0x00, 0x20, 0x00, 0x42, 0x00,
				0x50, 0x00, 0x62, 0x00, 0x92, 0x01, 0x00, 0x9a,
				0x01, 0x00, 0xa2, 0x01, 0x0c, 0x08, 0x00, 0x12,
				0x00, 0x18, 0x00, 0x20, 0x00, 0x28, 0x00, 0x3a,
				0x00},
		},
		Video: &media.VideoExtBizInfo{},
		Ptt:   &media.PttExtBizInfo{},
	}
}

func AudioDefault() media.ExtBizInfo {
	return media.ExtBizInfo{
		Pic:   &media.PicExtBizInfo{},
		Video: &media.VideoExtBizInfo{},
		Ptt: &media.PttExtBizInfo{
			BytesReserve:   []byte{0x03, 0x00, 0x38, 0x00},
			BytesPbReserve: []byte{},
			BytesGeneralFlags: []byte{
				0x9a, 0x01, 0x0b, 0xaa, 0x03, 0x08, 0x08, 0x04,
				0x12, 0x04, 0x00, 0x00, 0x00, 0x00},
		},
	}
}

func VideoDefault() media.ExtBizInfo {
	return media.ExtBizInfo{
		Pic: &media.PicExtBizInfo{},
		Video: &media.VideoExtBizInfo{
			BytesPbReserve: []byte{0x80, 0x01, 0x00},
		},
		Ptt: &media.PttExtBizInfo{},
	}
}

type Response interface{}

type UploadAccess struct {
	NtElem               []byte
	MsgInfoBody          []*media.MsgInfoBody
	CompatNotOnlineImage interface{}
	ImageFileId          int
}

type FileExists struct {
	UploadAccess UploadAccess
}

type UploadTicket struct {
	UKey        string
	IPv4s       []*media.IPv4
	SubFileType uint32
}

type RequireUpload struct {
	UploadAccess      UploadAccess
	UploadRequired    UploadTicket
	UploadSubRequired []UploadTicket
}

type DownloadAccess struct {
	FileUrl      string
	RKeyUrlParam string
}

type FileDownload struct {
	DownloadAccess DownloadAccess
}

func toIPv4AddressString(ip uint32) string {
	var result [4]string
	for i := 3; i >= 0; i-- {
		result[i] = strconv.FormatUint(uint64(ip&0xFF), 10)
		ip >>= 8
	}
	return fmt.Sprintf("%s.%s.%s.%s", result[3], result[2], result[1], result[0])
}
func ipv4Cover(ips []*media.IPv4) []*highway.NTHighwayIPv4 {
	if ips == nil {
		return []*highway.NTHighwayIPv4{}
	}

	var result []*highway.NTHighwayIPv4
	for _, ipv4 := range ips {
		result = append(result, &highway.NTHighwayIPv4{
			Domain: &highway.NTHighwayDomain{
				IsEnable: true,
				IP:       toIPv4AddressString(ipv4.OutIP),
			},
			Port: ipv4.OutPort,
		})
	}
	return result
}
func (context RequireUpload) RichMediaHighwayExt(resource io.ReadSeeker, fileSize uint32, subType uint32) ([]byte, error) {
	blockSize := 1024 * 1024
	var sha1List [][]byte

	buffer := make([]byte, sha1Plus.SHA1_BLOCK_SIZE)
	sha1Context := sha1Plus.NewSha1Plus()
	var hasRead uint32 = 0
	for {
		n, err := resource.Read(buffer)
		if err != nil && err != io.EOF {
			return nil, err
		}
		if n == 0 {
			break
		}

		hasRead += uint32(n)
		sha1Context.Update(buffer[:n])

		if hasRead%uint32(blockSize) == 0 && hasRead != fileSize {
			sha1List = append(sha1List, sha1Context.NonFinal())
		}
	}
	if hasRead%uint32(blockSize) != 0 {
		sha1List = append(sha1List, sha1Context.Final())
	}

	var msgInfo *media.MsgInfoBody
	for _, info := range context.UploadAccess.MsgInfoBody {
		if info.Index.SubType == subType {
			msgInfo = info
			break
		}
	}
	if msgInfo == nil {
		return nil, errors.New("cannot find subType")
	}

	var uploadInfo UploadTicket
	if subType == 0 {
		uploadInfo = context.UploadRequired
	} else {
		for _, info := range context.UploadSubRequired {
			if info.SubFileType == subType {
				uploadInfo = info
				break
			}
		}
		if uploadInfo.UKey == "" {
			return []byte{}, errors.New("cannot find subType")
		}
	}

	return proto.Marshal(&highway.NTV2RichMediaHighwayExt{
		FileUuid: msgInfo.Index.FileUuid,
		UKey:     uploadInfo.UKey,
		Network: &highway.NTHighwayNetwork{
			IPv4S: ipv4Cover(uploadInfo.IPv4s),
		},
		MsgInfoBody: context.UploadAccess.MsgInfoBody,
		BlockSize:   uint32(blockSize),
		Hash: &highway.NTHighwayHash{
			FileSha1: sha1List,
		},
	})
}
