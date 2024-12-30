// Code generated by protoc-gen-golite. DO NOT EDIT.
// source: pb/data.proto

package pb

type SSOReserveField struct {
	Flag          int32          `protobuf:"varint,9,opt"`
	LocaleId      int32          `protobuf:"varint,11,opt"`
	Qimei         string         `protobuf:"bytes,12,opt"`
	NewconnFlag   int32          `protobuf:"varint,14,opt"`
	TraceParent   string         `protobuf:"bytes,15,opt"`
	Uid           string         `protobuf:"bytes,16,opt"`
	Imsi          int32          `protobuf:"varint,18,opt"`
	NetworkType   int32          `protobuf:"varint,19,opt"`
	IpStackType   int32          `protobuf:"varint,20,opt"`
	MessageType   int32          `protobuf:"varint,21,opt"`
	SecInfo       *SsoSecureInfo `protobuf:"bytes,24,opt"`
	NtCoreVersion int32          `protobuf:"varint,26,opt"`
	SsoIpOrigin   int32          `protobuf:"varint,28,opt"`
	_             [0]func()
}

type SsoSecureInfo struct {
	SecSig         []byte `protobuf:"bytes,1,opt"`
	SecDeviceToken []byte `protobuf:"bytes,2,opt"`
	SecExtra       []byte `protobuf:"bytes,3,opt"`
}

type DeviceInfo struct {
	Bootloader   string `protobuf:"bytes,1,opt"`
	ProcVersion  string `protobuf:"bytes,2,opt"`
	Codename     string `protobuf:"bytes,3,opt"`
	Incremental  string `protobuf:"bytes,4,opt"`
	Fingerprint  string `protobuf:"bytes,5,opt"`
	BootId       string `protobuf:"bytes,6,opt"`
	AndroidId    string `protobuf:"bytes,7,opt"`
	BaseBand     string `protobuf:"bytes,8,opt"`
	InnerVersion string `protobuf:"bytes,9,opt"`
	_            [0]func()
}

type RequestBody struct {
	RptConfigList []*ConfigSeq `protobuf:"bytes,1,rep"`
}

type ConfigSeq struct {
	Type    int32 `protobuf:"varint,1,opt"`
	Version int32 `protobuf:"varint,2,opt"`
	_       [0]func()
}

type D50ReqBody struct {
	Appid                   int64   `protobuf:"varint,1,opt"`
	MaxPkgSize              int32   `protobuf:"varint,2,opt"`
	StartTime               int32   `protobuf:"varint,3,opt"`
	StartIndex              int32   `protobuf:"varint,4,opt"`
	ReqNum                  int32   `protobuf:"varint,5,opt"`
	UinList                 []int64 `protobuf:"varint,6,rep"`
	ReqMusicSwitch          int32   `protobuf:"varint,91001,opt"`
	ReqMutualmarkAlienation int32   `protobuf:"varint,101001,opt"`
	ReqMutualmarkScore      int32   `protobuf:"varint,141001,opt"`
	ReqKsingSwitch          int32   `protobuf:"varint,151001,opt"`
	ReqMutualmarkLbsshare   int32   `protobuf:"varint,181001,opt"`
}

type ReqDataHighwayHead struct {
	MsgBasehead   *DataHighwayHead `protobuf:"bytes,1,opt"`
	MsgSeghead    *SegHead         `protobuf:"bytes,2,opt"`
	ReqExtendinfo []byte           `protobuf:"bytes,3,opt"`
	Timestamp     int64            `protobuf:"varint,4,opt"` //LoginSigHead? msgLoginSigHead = 5;
}

type RspDataHighwayHead struct {
	MsgBasehead   *DataHighwayHead `protobuf:"bytes,1,opt"`
	MsgSeghead    *SegHead         `protobuf:"bytes,2,opt"`
	ErrorCode     int32            `protobuf:"varint,3,opt"`
	AllowRetry    int32            `protobuf:"varint,4,opt"`
	Cachecost     int32            `protobuf:"varint,5,opt"`
	Htcost        int32            `protobuf:"varint,6,opt"`
	RspExtendinfo []byte           `protobuf:"bytes,7,opt"`
	Timestamp     int64            `protobuf:"varint,8,opt"`
	Range         int64            `protobuf:"varint,9,opt"`
	IsReset       int32            `protobuf:"varint,10,opt"`
}

type DataHighwayHead struct {
	Version    int32  `protobuf:"varint,1,opt"`
	Uin        string `protobuf:"bytes,2,opt"`
	Command    string `protobuf:"bytes,3,opt"`
	Seq        int32  `protobuf:"varint,4,opt"`
	RetryTimes int32  `protobuf:"varint,5,opt"`
	Appid      int32  `protobuf:"varint,6,opt"`
	Dataflag   int32  `protobuf:"varint,7,opt"`
	CommandId  int32  `protobuf:"varint,8,opt"`
	BuildVer   string `protobuf:"bytes,9,opt"`
	LocaleId   int32  `protobuf:"varint,10,opt"`
	_          [0]func()
}

type SegHead struct {
	Serviceid     int32  `protobuf:"varint,1,opt"`
	Filesize      int64  `protobuf:"varint,2,opt"`
	Dataoffset    int64  `protobuf:"varint,3,opt"`
	Datalength    int32  `protobuf:"varint,4,opt"`
	Rtcode        int32  `protobuf:"varint,5,opt"`
	Serviceticket []byte `protobuf:"bytes,6,opt"`
	Flag          int32  `protobuf:"varint,7,opt"`
	Md5           []byte `protobuf:"bytes,8,opt"`
	FileMd5       []byte `protobuf:"bytes,9,opt"`
	CacheAddr     int32  `protobuf:"varint,10,opt"`
	QueryTimes    int32  `protobuf:"varint,11,opt"`
	UpdateCacheip int32  `protobuf:"varint,12,opt"`
}

type DeleteMessageRequest struct {
	Items []*MessageItem `protobuf:"bytes,1,rep"`
}

type MessageItem struct {
	FromUin int64  `protobuf:"varint,1,opt"`
	ToUin   int64  `protobuf:"varint,2,opt"`
	MsgType int32  `protobuf:"varint,3,opt"`
	MsgSeq  int32  `protobuf:"varint,4,opt"`
	MsgUid  int64  `protobuf:"varint,5,opt"`
	Sig     []byte `protobuf:"bytes,7,opt"`
}

type SubD4 struct {
	Uin int64 `protobuf:"varint,1,opt"`
	_   [0]func()
}

type Sub8A struct {
	MsgInfo         []*Sub8AMsgInfo `protobuf:"bytes,1,rep"`
	AppId           int32           `protobuf:"varint,2,opt"`
	InstId          int32           `protobuf:"varint,3,opt"`
	LongMessageFlag int32           `protobuf:"varint,4,opt"`
	Reserved        []byte          `protobuf:"bytes,5,opt"`
}

type Sub8AMsgInfo struct {
	FromUin   int64 `protobuf:"varint,1,opt"`
	ToUin     int64 `protobuf:"varint,2,opt"`
	MsgSeq    int32 `protobuf:"varint,3,opt"`
	MsgUid    int64 `protobuf:"varint,4,opt"`
	MsgTime   int64 `protobuf:"varint,5,opt"`
	MsgRandom int32 `protobuf:"varint,6,opt"`
	PkgNum    int32 `protobuf:"varint,7,opt"`
	PkgIndex  int32 `protobuf:"varint,8,opt"`
	DevSeq    int32 `protobuf:"varint,9,opt"`
	_         [0]func()
}

type SubB3 struct {
	Type            int32              `protobuf:"varint,1,opt"`
	MsgAddFrdNotify *SubB3AddFrdNotify `protobuf:"bytes,2,opt"`
	_               [0]func()
}

type SubB3AddFrdNotify struct {
	Uin  int64  `protobuf:"varint,1,opt"`
	Nick string `protobuf:"bytes,5,opt"`
	_    [0]func()
}

type Sub44 struct {
	FriendSyncMsg *Sub44FriendSyncMsg `protobuf:"bytes,1,opt"`
	GroupSyncMsg  *Sub44GroupSyncMsg  `protobuf:"bytes,2,opt"`
	_             [0]func()
}

type Sub44FriendSyncMsg struct {
	Uin         int64    `protobuf:"varint,1,opt"`
	FUin        int64    `protobuf:"varint,2,opt"`
	ProcessType int32    `protobuf:"varint,3,opt"`
	Time        int32    `protobuf:"varint,4,opt"`
	ProcessFlag int32    `protobuf:"varint,5,opt"`
	SourceId    int32    `protobuf:"varint,6,opt"`
	SourceSubId int32    `protobuf:"varint,7,opt"`
	StrWording  []string `protobuf:"bytes,8,rep"`
}

type Sub44GroupSyncMsg struct {
	MsgType         int32  `protobuf:"varint,1,opt"`
	MsgSeq          int64  `protobuf:"varint,2,opt"`
	GrpCode         int64  `protobuf:"varint,3,opt"`
	GaCode          int64  `protobuf:"varint,4,opt"`
	OptUin1         int64  `protobuf:"varint,5,opt"`
	OptUin2         int64  `protobuf:"varint,6,opt"`
	MsgBuf          []byte `protobuf:"bytes,7,opt"`
	AuthKey         []byte `protobuf:"bytes,8,opt"`
	MsgStatus       int32  `protobuf:"varint,9,opt"`
	ActionUin       int64  `protobuf:"varint,10,opt"`
	ActionTime      int64  `protobuf:"varint,11,opt"`
	CurMaxMemCount  int32  `protobuf:"varint,12,opt"`
	NextMaxMemCount int32  `protobuf:"varint,13,opt"`
	CurMemCount     int32  `protobuf:"varint,14,opt"`
	ReqSrcId        int32  `protobuf:"varint,15,opt"`
	ReqSrcSubId     int32  `protobuf:"varint,16,opt"`
	InviterRole     int32  `protobuf:"varint,17,opt"`
	ExtAdminNum     int32  `protobuf:"varint,18,opt"`
	ProcessFlag     int32  `protobuf:"varint,19,opt"`
}

type GroupMemberReqBody struct {
	GroupCode       int64 `protobuf:"varint,1,opt"`
	Uin             int64 `protobuf:"varint,2,opt"`
	NewClient       bool  `protobuf:"varint,3,opt"`
	ClientType      int32 `protobuf:"varint,4,opt"`
	RichCardNameVer int32 `protobuf:"varint,5,opt"`
	_               [0]func()
}

type GroupMemberRspBody struct {
	GroupCode              int64            `protobuf:"varint,1,opt"`
	SelfRole               int32            `protobuf:"varint,2,opt"`
	MemInfo                *GroupMemberInfo `protobuf:"bytes,3,opt"`
	BoolSelfLocationShared bool             `protobuf:"varint,4,opt"`
	GroupType              int32            `protobuf:"varint,5,opt"`
	_                      [0]func()
}

type GroupMemberInfo struct {
	Uin         int64  `protobuf:"varint,1,opt"`
	Result      int32  `protobuf:"varint,2,opt"`
	Errmsg      []byte `protobuf:"bytes,3,opt"`
	IsFriend    bool   `protobuf:"varint,4,opt"`
	Remark      []byte `protobuf:"bytes,5,opt"`
	IsConcerned bool   `protobuf:"varint,6,opt"`
	Credit      int32  `protobuf:"varint,7,opt"`
	Card        []byte `protobuf:"bytes,8,opt"`
	Sex         int32  `protobuf:"varint,9,opt"`
	Location    []byte `protobuf:"bytes,10,opt"`
	Nick        []byte `protobuf:"bytes,11,opt"`
	Age         int32  `protobuf:"varint,12,opt"`
	Lev         []byte `protobuf:"bytes,13,opt"`
	Join        int64  `protobuf:"varint,14,opt"`
	LastSpeak   int64  `protobuf:"varint,15,opt"`
	// repeated CustomEntry customEnties = 16;
	// repeated GBarInfo gbarConcerned = 17;
	GbarTitle              []byte `protobuf:"bytes,18,opt"`
	GbarUrl                []byte `protobuf:"bytes,19,opt"`
	GbarCnt                int32  `protobuf:"varint,20,opt"`
	IsAllowModCard         bool   `protobuf:"varint,21,opt"`
	IsVip                  bool   `protobuf:"varint,22,opt"`
	IsYearVip              bool   `protobuf:"varint,23,opt"`
	IsSuperVip             bool   `protobuf:"varint,24,opt"`
	IsSuperQq              bool   `protobuf:"varint,25,opt"`
	VipLev                 int32  `protobuf:"varint,26,opt"`
	Role                   int32  `protobuf:"varint,27,opt"`
	LocationShared         bool   `protobuf:"varint,28,opt"`
	Int64Distance          int64  `protobuf:"varint,29,opt"`
	ConcernType            int32  `protobuf:"varint,30,opt"`
	SpecialTitle           []byte `protobuf:"bytes,31,opt"`
	SpecialTitleExpireTime int32  `protobuf:"varint,32,opt"`
	// FlowersEntry flowerEntry = 33;
	// TeamEntry teamEntry = 34;
	PhoneNum []byte `protobuf:"bytes,35,opt"`
	Job      []byte `protobuf:"bytes,36,opt"`
	MedalId  int32  `protobuf:"varint,37,opt"`
	Level    int32  `protobuf:"varint,39,opt"`
	Honor    string `protobuf:"bytes,41,opt"`
}
