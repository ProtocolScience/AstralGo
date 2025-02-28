package client

import (
	"crypto/md5"
	"fmt"
	"github.com/ProtocolScience/AstralGo/client/nt"
	"github.com/ProtocolScience/AstralGo/client/pb/database"
	"github.com/ProtocolScience/AstralGo/client/pb/trpc"
	"github.com/ProtocolScience/AstralGo/client/process"
	"github.com/ProtocolScience/AstralGo/internal/proto"
	log "github.com/sirupsen/logrus"
	"math/rand"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"

	"github.com/RomiChan/syncx"

	"github.com/ProtocolScience/AstralGo/binary"
	"github.com/ProtocolScience/AstralGo/client/internal/auth"
	"github.com/ProtocolScience/AstralGo/client/internal/highway"
	"github.com/ProtocolScience/AstralGo/client/internal/intern"
	"github.com/ProtocolScience/AstralGo/client/internal/network"
	"github.com/ProtocolScience/AstralGo/client/internal/oicq"
	"github.com/ProtocolScience/AstralGo/client/pb/msg"
	"github.com/ProtocolScience/AstralGo/message"
	"github.com/ProtocolScience/AstralGo/utils"
)

type QQClient struct {
	Uin         int64
	PasswordMd5 [16]byte

	stat       Statistics
	once       sync.Once
	InitWaitMu sync.Mutex
	InitWait   *sync.Cond

	// option
	AllowSlider        bool
	UseFragmentMessage bool

	// account info
	Online        atomic.Bool
	Nickname      string
	Age           uint16
	Gender        uint16
	FriendList    []*FriendInfo
	GroupList     []*GroupInfo
	OnlineClients []*OtherClientInfo
	QiDian        *QiDianAccountInfo
	GuildService  *GuildService

	// protocol public field
	SequenceId  atomic.Int32
	SessionId   []byte
	TCP         *network.TCPClient // todo: combine other protocol state into one struct
	ConnectTime time.Time

	transport *network.Transport
	oicq      *oicq.Codec
	logger    Logger

	// internal state
	handlers        syncx.Map[uint16, *handlerInfo]
	waiters         syncx.Map[string, func(any, error)]
	initServerOnce  sync.Once
	servers         []netip.AddrPort
	currServerIndex int
	retryTimes      int
	alive           bool

	// session info
	qwebSeq        atomic.Int64
	sig            *auth.SigInfo
	highwaySession *highway.Session
	// pwdFlag        bool
	// timeDiff       int64

	// address
	// otherSrvAddrs   []string
	// fileStorageInfo *jce.FileStoragePushFSSvcList

	// event handles
	eventHandlers                     eventHandlers
	PrivateMessageEvent               EventHandle[*message.PrivateMessage]
	TempMessageEvent                  EventHandle[*TempMessageEvent]
	GroupMessageEvent                 EventHandle[*message.GroupMessage]
	SelfPrivateMessageEvent           EventHandle[*message.PrivateMessage]
	SelfGroupMessageEvent             EventHandle[*message.GroupMessage]
	GroupMuteEvent                    EventHandle[*GroupMuteEvent]
	GroupMessageRecalledEvent         EventHandle[*GroupMessageRecalledEvent]
	FriendMessageRecalledEvent        EventHandle[*FriendMessageRecalledEvent]
	GroupJoinEvent                    EventHandle[*GroupInfo]
	GroupLeaveEvent                   EventHandle[*GroupLeaveEvent]
	GroupMemberJoinEvent              EventHandle[*MemberJoinGroupEvent]
	GroupMemberLeaveEvent             EventHandle[*MemberLeaveGroupEvent]
	MemberCardUpdatedEvent            EventHandle[*MemberCardUpdatedEvent]
	GroupNameUpdatedEvent             EventHandle[*GroupNameUpdatedEvent]
	GroupMemberPermissionChangedEvent EventHandle[*MemberPermissionChangedEvent]
	GroupInvitedEvent                 EventHandle[*GroupInvitedRequest]
	UserWantJoinGroupEvent            EventHandle[*UserJoinGroupRequest]
	NewFriendEvent                    EventHandle[*NewFriendEvent]
	NewFriendRequestEvent             EventHandle[*NewFriendRequest]
	DisconnectedEvent                 EventHandle[*DisconnectedEvent]
	GroupNotifyEvent                  EventHandle[INotifyEvent]
	FriendNotifyEvent                 EventHandle[INotifyEvent]
	MemberSpecialTitleUpdatedEvent    EventHandle[*MemberSpecialTitleUpdatedEvent]
	GroupDigestEvent                  EventHandle[*GroupDigestEvent]
	OtherClientStatusChangedEvent     EventHandle[*OtherClientStatusChangedEvent]
	OfflineFileEvent                  EventHandle[*OfflineFileEvent]
	GroupDisbandEvent                 EventHandle[*GroupDisbandEvent]
	DeleteFriendEvent                 EventHandle[*DeleteFriendEvent]

	// message state
	msgSvcCache            *utils.Cache[unit]
	lastC2CMsgTime         int64
	transCache             *utils.Cache[unit]
	groupSysMsgCache       *GroupSystemMessages
	msgBuilders            syncx.Map[int32, *messageBuilder]
	onlinePushCache        *utils.Cache[unit]
	voiceUploadCache       *utils.Cache[message.NewTechVoiceElement]
	heartbeatEnabled       bool
	requestPacketRequestID atomic.Int32
	groupSeq               atomic.Int32
	friendSeq              atomic.Int32
	highwayApplyUpSeq      atomic.Int32

	groupListLock     sync.Mutex
	rKeyLock          sync.Mutex
	RKey              nt.RKeyMap
	firstLoginSucceed bool
}

type QiDianAccountInfo struct {
	MasterUin  int64
	ExtName    string
	CreateTime int64

	bigDataReqAddrs   []string
	bigDataReqSession *bigDataSessionInfo
}

type handlerInfo struct {
	fun     func(i any, err error)
	dynamic bool
	params  network.RequestParams
}

func (h *handlerInfo) getParams() network.RequestParams {
	if h == nil {
		return nil
	}
	return h.params
}

var decoders = map[string]func(*QQClient, *network.Packet) (any, error){
	"wtlogin.login":                                decodeLoginResponse,
	"wtlogin.exchange_emp":                         decodeExchangeEmpResponse,
	"wtlogin.trans_emp":                            decodeTransEmpResponse,
	"StatSvc.register":                             decodeClientRegisterResponse,
	"StatSvc.ReqMSFOffline":                        decodeMSFOfflinePacket,
	"MessageSvc.PushNotify":                        decodeSvcNotify,
	"OnlinePush.SidTicketExpired":                  decodeSidExpiredPacket,
	"ConfigPushSvc.PushReq":                        decodePushReqPacket,
	"MessageSvc.PbGetMsg":                          decodeMessageSvcPacket,
	"MessageSvc.PushForceOffline":                  decodeForceOfflinePacket,
	"PbMessageSvc.PbMsgWithDraw":                   decodeMsgWithDrawResponse,
	"friendlist.getFriendGroupList":                decodeFriendGroupListResponse,
	"friendlist.delFriend":                         decodeFriendDeleteResponse,
	"friendlist.GetTroopListReqV2":                 decodeGroupListResponse,
	"friendlist.GetTroopMemberListReq":             decodeGroupMemberListResponse,
	"group_member_card.get_group_member_card_info": decodeGroupMemberInfoResponse,
	"LongConn.OffPicUp":                            decodeOffPicUpResponse,
	"ProfileService.Pb.ReqSystemMsgNew.Group":      decodeSystemMsgGroupPacket,
	"ProfileService.Pb.ReqSystemMsgNew.Friend":     decodeSystemMsgFriendPacket,
	"OidbSvc.0xd79":                                decodeWordSegmentation,
	"OidbSvc.0x990":                                decodeTranslateResponse,
	"SummaryCard.ReqSummaryCard":                   decodeSummaryCardResponse,
}

// NewClient create new qq client
func NewClient(uin int64, password string) *QQClient {
	return NewClientMd5(uin, md5.Sum([]byte(password)))
}

func NewClientEmpty() *QQClient {
	return NewClientMd5(0, [16]byte{})
}

func NewClientMd5(uin int64, passwordMd5 [16]byte) *QQClient {
	cli := &QQClient{
		Uin:         uin,
		PasswordMd5: passwordMd5,
		AllowSlider: true,
		TCP:         &network.TCPClient{},
		sig: &auth.SigInfo{
			OutPacketSessionID: []byte{0x02, 0xB0, 0x5B, 0x8B},
		},
		msgSvcCache:       utils.NewCache[unit](time.Second * 15),
		transCache:        utils.NewCache[unit](time.Second * 15),
		onlinePushCache:   utils.NewCache[unit](time.Second * 15),
		voiceUploadCache:  utils.NewCache[message.NewTechVoiceElement](time.Second * 15),
		alive:             true,
		highwaySession:    new(highway.Session),
		firstLoginSucceed: false,
	}
	cli.InitWait = sync.NewCond(&cli.InitWaitMu)

	cli.transport = &network.Transport{Sig: cli.sig}
	cli.oicq = oicq.NewCodec(cli.Uin)
	{ // init atomic values
		cli.SequenceId.Store(int32(rand.Intn(100000)))
		cli.requestPacketRequestID.Store(1921334513)
		cli.groupSeq.Store(int32(rand.Intn(20000)))
		cli.friendSeq.Store(22911)
		cli.highwayApplyUpSeq.Store(77918)
	}
	cli.highwaySession.Uin = strconv.FormatInt(cli.Uin, 10)
	cli.GuildService = &GuildService{c: cli}
	cli.TCP.PlannedDisconnect(cli.plannedDisconnect)
	cli.TCP.UnexpectedDisconnect(cli.unexpectedDisconnect)
	return cli
}

func (c *QQClient) WaitInit(wait bool) {
	c.InitWaitMu.Lock()
	if c.InitWait != nil {
		if wait {
			c.InitWait.Wait()
		} else {
			c.InitWait.Broadcast()
		}
		c.InitWait = nil
	}
	c.InitWaitMu.Unlock()
}

func (c *QQClient) version() *auth.AppVersion {
	return c.transport.Version
}

func (c *QQClient) Device() *DeviceInfo {
	return c.transport.Device
}

func (c *QQClient) UseDevice(info *auth.Device) {
	c.transport.Version = info.Protocol.Version()
	c.transport.Device = info
	c.highwaySession.AppID = c.version().AppId
	c.sig.Ksid = []byte(fmt.Sprintf("|%s|A8.2.7.27f6ea96", info.IMEI))
}

func (c *QQClient) Release() {
	if c.Online.Load() {
		c.Disconnect()
	}
	c.alive = false
}

// Login send login request
func (c *QQClient) Login() (*LoginResponse, error) {
	if c.Online.Load() {
		return nil, ErrAlreadyOnline
	}
	err := c.connect()
	if err != nil {
		return nil, err
	}
	rsp, err := c.PasswordLogin()
	if err != nil {
		c.Disconnect()
		return nil, err
	}
	return rsp, err
}

func (c *QQClient) PasswordLogin() (*LoginResponse, error) {
	rsp, err := c.sendAndWait(c.buildLoginPacket())
	l := rsp.(LoginResponse)
	if l.Success {
		err = c.init(false)
	}
	return &l, err
}

func (c *QQClient) TokenLogin(token []byte) error {
	if c.Online.Load() {
		return ErrAlreadyOnline
	}
	err := c.connect()
	if err != nil {
		return err
	}
	{
		r := binary.NewReader(token)
		c.Uin = r.ReadInt64()
		c.sig.D2 = r.ReadBytesShort()
		c.sig.D2Key = r.ReadBytesShort()
		c.sig.TGT = r.ReadBytesShort()
		c.sig.SrmToken = r.ReadBytesShort()
		c.sig.T133 = r.ReadBytesShort()
		c.sig.EncryptedA1 = r.ReadBytesShort()
		c.oicq.WtSessionTicketKey = r.ReadBytesShort()
		c.sig.OutPacketSessionID = r.ReadBytesShort()
		// SystemDeviceInfo.TgtgtKey = r.ReadBytesShort()
		c.Device().TgtgtKey = r.ReadBytesShort()
	}
	_, err = c.sendAndWait(c.buildRequestChangeSigPacket(true))
	if err != nil {
		return err
	}
	return c.init(true)
}

func (c *QQClient) FetchQRCode() (*QRCodeLoginResponse, error) {
	return c.FetchQRCodeCustomSize(3, 4, 2)
}

func (c *QQClient) FetchQRCodeCustomSize(size, margin, ecLevel uint32) (*QRCodeLoginResponse, error) {
	if c.Online.Load() {
		return nil, ErrAlreadyOnline
	}
	err := c.connect()
	if err != nil {
		return nil, err
	}
	i, err := c.sendAndWait(c.buildQRCodeFetchRequestPacket(size, margin, ecLevel))
	if err != nil {
		return nil, errors.Wrap(err, "fetch qrcode error")
	}
	return i.(*QRCodeLoginResponse), nil
}

func (c *QQClient) QueryQRCodeStatus(sig []byte) (*QRCodeLoginResponse, error) {
	i, err := c.sendAndWait(c.buildQRCodeResultQueryRequestPacket(sig))
	if err != nil {
		return nil, errors.Wrap(err, "query result error")
	}
	return i.(*QRCodeLoginResponse), nil
}

func (c *QQClient) QRCodeLogin(info *QRCodeLoginInfo) (*LoginResponse, error) {
	i, err := c.sendAndWait(c.buildQRCodeLoginPacket(info.tmpPwd, info.tmpNoPicSig, info.tgtQR))
	if err != nil {
		return nil, errors.Wrap(err, "qrcode login error")
	}
	rsp := i.(LoginResponse)
	if rsp.Success {
		err = c.init(false)
	}
	return &rsp, err
}

// SubmitCaptcha send captcha to server
func (c *QQClient) SubmitCaptcha(result string, sign []byte) (*LoginResponse, error) {
	seq, packet := c.buildCaptchaPacket(result, sign)
	rsp, err := c.sendAndWait(seq, packet)
	if err != nil {
		c.Disconnect()
		return nil, err
	}
	l := rsp.(LoginResponse)
	if l.Success {
		err = c.init(false)
	}
	return &l, err
}

func (c *QQClient) SubmitTicket(ticket string) (*LoginResponse, error) {
	seq, packet := c.buildTicketSubmitPacket(ticket)
	rsp, err := c.sendAndWait(seq, packet)
	if err != nil {
		c.Disconnect()
		return nil, err
	}
	l := rsp.(LoginResponse)
	if l.Success {
		err = c.init(false)
	}
	return &l, err
}

func (c *QQClient) SubmitSMS(code string) (*LoginResponse, error) {
	rsp, err := c.sendAndWait(c.buildSMSCodeSubmitPacket(code))
	if err != nil {
		c.Disconnect()
		return nil, err
	}
	l := rsp.(LoginResponse)
	if l.Success {
		err = c.init(false)
	}
	return &l, err
}

func (c *QQClient) RequestSMS() bool {
	rsp, err := c.sendAndWait(c.buildSMSRequestPacket())
	if err != nil {
		c.error("request sms error: %v", err)
		return false
	}
	return rsp.(LoginResponse).Error == SMSNeededError
}

func (c *QQClient) init(tokenLogin bool) error {
	c.highwaySession.Uin = strconv.FormatInt(c.Uin, 10)
	if err := c.registerClient(); err != nil {
		return errors.Wrap(err, "register error")
	}
	if tokenLogin {
		notify := make(chan struct{}, 2)
		d := c.waitPacket("StatSvc.ReqMSFOffline", func(i any, err error) {
			notify <- struct{}{}
		})
		d2 := c.waitPacket("MessageSvc.PushForceOffline", func(i any, err error) {
			notify <- struct{}{}
		})
		select {
		case <-notify:
			d()
			d2()
			return errors.New("token failed")
		case <-time.After(time.Second):
			d()
			d2()
		}
	}
	c.groupSysMsgCache, _ = c.GetGroupSystemMessages()
	if !c.heartbeatEnabled {
		go c.doHeartbeat()
	}
	_ = c.RefreshStatus()
	if c.version().Protocol == auth.QiDian {
		_, _ = c.sendAndWait(c.buildLoginExtraPacket()) // 小登录
	}
	seq, pkt := c.buildGetMessageRequestPacket(msg.SyncFlag_START, time.Now().Unix())
	_, _ = c.sendAndWait(seq, pkt, network.RequestParams{"used_reg_proxy": true, "init": true})
	c.syncChannelFirstView()
	return nil
}

func (c *QQClient) GetUINByUID(uid string) int64 {
	query := utils.UIDGlobalCaches.GetByUID(uid)
	if query == nil {
		rsp, err := c.sendAndWait(c.buildUID2UINRequestPacket(uid))
		if err != nil {
			return 0
		}
		uin := rsp.(int64)
		utils.UIDGlobalCaches.Add(uid, uin)
		return uin
	} else {
		return query.UIN
	}
}
func (c *QQClient) GenToken() []byte {
	return binary.NewWriterF(func(w *binary.Writer) {
		w.WriteUInt64(uint64(c.Uin))
		w.WriteBytesShort(c.sig.D2)
		w.WriteBytesShort(c.sig.D2Key)
		w.WriteBytesShort(c.sig.TGT)
		w.WriteBytesShort(c.sig.SrmToken)
		w.WriteBytesShort(c.sig.T133)
		w.WriteBytesShort(c.sig.EncryptedA1)
		w.WriteBytesShort(c.oicq.WtSessionTicketKey)
		w.WriteBytesShort(c.sig.OutPacketSessionID)
		w.WriteBytesShort(c.Device().TgtgtKey)
	})
}

func (c *QQClient) SetOnlineStatus(s UserOnlineStatus) {
	if s < 1000 {
		_, _ = c.sendAndWait(c.buildStatusSetPacket(int32(s), 0))
		return
	}
	_, _ = c.sendAndWait(c.buildStatusSetPacket(11, int32(s)))
}

func (c *QQClient) GetWordSegmentation(text string) ([]string, error) {
	rsp, err := c.sendAndWait(c.buildWordSegmentationPacket([]byte(text)))
	if err != nil {
		return nil, err
	}
	if data, ok := rsp.([][]byte); ok {
		var ret []string
		for _, val := range data {
			ret = append(ret, string(val))
		}
		return ret, nil
	}
	return nil, errors.New("decode error")
}

func (c *QQClient) GetSummaryInfo(target int64) (*SummaryCardInfo, error) {
	rsp, err := c.sendAndWait(c.buildSummaryCardRequestPacket(target))
	if err != nil {
		return nil, err
	}
	return rsp.(*SummaryCardInfo), nil
}

// ReloadFriendList refresh QQClient.FriendList field via GetFriendList()
func (c *QQClient) ReloadFriendList() error {
	rsp, err := c.GetFriendList()
	if err != nil {
		return err
	}
	c.FriendList = rsp.List
	return nil
}

// GetFriendList
// 当使用普通QQ时: 请求好友列表
// 当使用企点QQ时: 请求外部联系人列表
func (c *QQClient) GetFriendList() (*FriendListResponse, error) {
	if c.version().Protocol == auth.QiDian {
		rsp, err := c.getQiDianAddressDetailList()
		if err != nil {
			return nil, err
		}
		return &FriendListResponse{TotalCount: int32(len(rsp)), List: rsp}, nil
	}
	curFriendCount := 0
	/*
		r := &FriendListResponse{}
		for {
			rsp, err := c.sendAndWait(c.buildFriendGroupListRequestPacket(int16(curFriendCount), 150, 0, 0))
			if err != nil {
				return nil, err
			}
			list := rsp.(*FriendListResponse)
			r.TotalCount = list.TotalCount
			r.List = append(r.List, list.List...)
			curFriendCount += len(list.List)
			if int32(len(r.List)) >= r.TotalCount {
				break
			}
		}*/

	r := &FriendListResponse{}
	var continueToken []byte = nil
	for {
		rsp, err := c.sendAndWait(c.buildNewFriendGroupListRequestPacket(continueToken))
		list := rsp.(*NTFriendListResponse)
		if err != nil {
			return nil, err
		} else {
			continueToken = list.ContinueToken
			r.List = append(r.List, list.List...)
			curFriendCount += len(list.List)
			if list.ContinueToken == nil {
				break
			}
		}
	}
	for _, t := range r.List {
		utils.UIDGlobalCaches.Add(t.Uid, t.Uin)
	}
	r.TotalCount = int32(len(r.List))
	return r, nil
}

func (c *QQClient) SendGroupPoke(groupCode, target int64) {
	_, _ = c.sendAndWait(c.buildGroupPokePacket(groupCode, target))
}

func (c *QQClient) SendFriendPoke(target int64) {
	_, _ = c.sendAndWait(c.buildFriendPokePacket(target))
}

func (c *QQClient) ReloadGroupList() error {
	c.groupListLock.Lock()
	defer c.groupListLock.Unlock()
	list, err := c.GetGroupList()
	if err != nil {
		return err
	}
	c.GroupList = list
	return nil
}
func (c *QQClient) ReloadGroup(groupCode int64) (*GroupInfo, error) {
	interned := intern.NewStringInterner()
	g, err := c.GetGroupInfo(groupCode)
	if err != nil {
		return nil, err
	}
	m, err := c.getGroupMembers(g, interned)
	if err != nil {
		return nil, err
	}
	g.Members = m
	g.Name = interned.Intern(g.Name)
	if c.FindGroupByUin(groupCode) == nil {
		c.GroupList = append(c.GroupList, g)
	}
	return g, nil
}
func (c *QQClient) GetGroupList() ([]*GroupInfo, error) {
	rsp, err := c.sendAndWait(c.buildNewGroupListRequestPacket())
	if err != nil {
		return nil, err
	}
	interned := intern.NewStringInterner()
	r := rsp.([]*GroupInfo)

	var bar process.Bar
	wg := sync.WaitGroup{}
	batch := 25
	total := len(r)
	bar.NewOption(0, int64(total), 50)
	for i := 0; i < total; i += batch {
		k := i + batch
		if k > total {
			k = total
		}
		wg.Add(k - i)
		for j := i; j < k; j++ {
			go func(g *GroupInfo, wg *sync.WaitGroup) {
				defer wg.Done()
				m, err := c.getGroupMembers(g, interned)
				if err != nil {
					return
				}
				g.Members = m
				g.Name = interned.Intern(g.Name)
			}(r[j], &wg)
		}
		wg.Wait()
		bar.Play(int64(i))
	}
	bar.Play(int64(total))
	bar.Finish()
	return r, nil
}

func (c *QQClient) GetGroupMembers(group *GroupInfo) ([]*GroupMemberInfo, error) {
	interner := intern.NewStringInterner()
	return c.getGroupMembers(group, interner)
}

/*
func (c *QQClient) getGroupMembers(group *GroupInfo, interner *intern.StringInterner) ([]*GroupMemberInfo, error) {
	var nextUin int64
	var list []*GroupMemberInfo
	for {
		data, err := c.sendAndWait(c.buildGroupMemberListRequestPacket(group.Uin, group.Code, nextUin))
		if err != nil {
			return nil, err
		}
		if data == nil {
			return nil, errors.New("group members list is unavailable: rsp is nil")
		}
		rsp := data.(*groupMemberListResponse)
		nextUin = rsp.NextUin
		for _, m := range rsp.list {
			m.Group = group
			if m.Uin == group.OwnerUin {
				m.Permission = Owner
			}
			m.CardName = interner.Intern(m.CardName)
			m.Nickname = interner.Intern(m.Nickname)
			m.SpecialTitle = interner.Intern(m.SpecialTitle)
		}
		list = append(list, rsp.list...)
		if nextUin == 0 {
			sort.Slice(list, func(i, j int) bool {
				return list[i].Uin < list[j].Uin
			})
			return list, nil
		}
	}
}*/

func (c *QQClient) getGroupMembers(group *GroupInfo, interner *intern.StringInterner) ([]*GroupMemberInfo, error) {
	var nextUin int64
	var list []*GroupMemberInfo
	var requestToken string
	for {
		if c.version().Protocol == auth.AndroidWatch { //Legacy Packet，手表目前没完全NT化，需要用这个包
			data, err := c.sendAndWait(c.buildGroupMemberListRequestPacket(group.Uin, group.Code, nextUin))
			if err != nil {
				return nil, err
			}
			if data == nil {
				return nil, errors.New("group members list is unavailable: rsp is nil")
			}
			rsp := data.(*groupMemberListResponse)
			nextUin = rsp.NextUin
			for _, m := range rsp.list {
				m.Group = group
				if m.Uin == group.OwnerUin {
					m.Permission = Owner
				}
				m.CardName = interner.Intern(m.CardName)
				m.Nickname = interner.Intern(m.Nickname)
				m.SpecialTitle = interner.Intern(m.SpecialTitle)
			}
			list = append(list, rsp.list...)
		} else {
			data, err := c.sendAndWait(c.buildNewGetTroopMemberListRequestPacket(group.Code, nil, nil, requestToken))
			if err != nil {
				log.Warnf("get group members failed! group: %d err: %v ", group.Code, err.Error())
				return nil, err
			}
			if data == nil {
				return nil, errors.New("group members list is unavailable: rsp is nil")
			}
			rsp := data.(*NTGroupMemberListResponse)
			requestToken = rsp.nextToken
			for _, m := range rsp.list {
				m.Group = group
				if m.Uin == group.OwnerUin {
					m.Permission = Owner
				}
				m.CardName = interner.Intern(m.CardName)
				m.Nickname = interner.Intern(m.Nickname)
				m.SpecialTitle = interner.Intern(m.SpecialTitle)
			}
			list = append(list, rsp.list...)
		}
		if requestToken == "" {
			sort.Slice(list, func(i, j int) bool {
				return list[i].Uin < list[j].Uin
			})
			for _, t := range list {
				utils.UIDGlobalCaches.Add(t.Uid, t.Uin)
			}
			return list, nil
		}
	}
}

func (c *QQClient) GetMemberInfo(groupCode, memberUin int64) (*GroupMemberInfo, error) {
	info, err := c.sendAndWait(c.buildGroupMemberInfoRequestPacket(groupCode, memberUin))
	if err != nil {
		return nil, err
	}
	return info.(*GroupMemberInfo), nil
}

func (c *QQClient) FindFriend(uin int64) *FriendInfo {
	if uin == c.Uin {
		return &FriendInfo{
			Uin:      uin,
			Nickname: c.Nickname,
		}
	}
	for _, t := range c.FriendList {
		f := t
		if f.Uin == uin {
			return f
		}
	}
	return nil
}

func (c *QQClient) DeleteFriend(uin int64) error {
	if c.FindFriend(uin) == nil {
		return errors.New("friend not found")
	}
	_, err := c.sendAndWait(c.buildFriendDeletePacket(uin))
	return errors.Wrap(err, "delete friend error")
}

func (c *QQClient) FindGroupByUin(uin int64) *GroupInfo {
	for _, g := range c.GroupList {
		f := g
		if f.Uin == uin {
			return f
		}
	}
	return nil
}

func (c *QQClient) FindGroup(code int64) *GroupInfo {
	for _, g := range c.GroupList {
		if g.Code == code {
			return g
		}
	}
	return nil
}

func (c *QQClient) SolveGroupJoinRequest(i any, accept, block bool, reason string) {
	if accept {
		block = false
		reason = ""
	}

	switch req := i.(type) {
	case *UserJoinGroupRequest:
		_, pkt := c.buildSystemMsgGroupActionPacket(req.RequestId, req.RequesterUin, req.GroupCode, func() int32 {
			if req.Suspicious {
				return 2
			} else {
				return 1
			}
		}(), false, accept, block, reason)
		_ = c.sendPacket(pkt)
	case *GroupInvitedRequest:
		_, pkt := c.buildSystemMsgGroupActionPacket(req.RequestId, req.InvitorUin, req.GroupCode, 1, true, accept, block, reason)
		_ = c.sendPacket(pkt)
	}
}

func (c *QQClient) SolveFriendRequest(req *NewFriendRequest, accept bool) {
	_, pkt := c.buildSystemMsgFriendActionPacket(req.RequestId, req.RequesterUin, accept)
	_ = c.sendPacket(pkt)
}
func (c *QQClient) GetRKey() (*nt.RKeyMap, error) {
	c.rKeyLock.Lock()
	if c.RKey != nil {
		for _, v := range c.RKey {
			if v.ExpireTime < uint64(time.Now().Unix()) {
				c.RKey = nil
				//log.Warn("rkey expired. refresh...")
				break
			}
		}
	}
	if c.RKey == nil {
		data, err := c.sendAndWait(c.BuildFetchRKeyReq())
		if err == nil {
			c.RKey = data.(nt.RKeyMap)
		}
	}
	if c.RKey == nil {
		c.RKey = nt.RKeyMap{
			nt.GroupImageRKey: &nt.RKeyInfo{
				RKeyType:   nt.GroupImageRKey,
				RKey:       "",
				ExpireTime: 0,
				CreateTime: 0,
			},
			nt.FriendImageRKey: &nt.RKeyInfo{
				RKeyType:   nt.FriendImageRKey,
				RKey:       "",
				ExpireTime: 0,
				CreateTime: 0,
			},
		}
	}
	defer c.rKeyLock.Unlock()
	return &c.RKey, nil
}
func (c *QQClient) getSKey() string {
	if c.sig.SKeyExpiredTime < time.Now().Unix() && len(c.sig.G) > 0 {
		c.debug("skey expired. refresh...")
		_, _ = c.sendAndWait(c.buildRequestTgtgtNopicsigPacket())
	}
	return string(c.sig.SKey)
}

func (c *QQClient) getCookies() string {
	return fmt.Sprintf("uin=o%d; skey=%s;", c.Uin, c.getSKey())
}

func (c *QQClient) getCookiesWithDomain(domain string) string {
	cookie := c.getCookies()

	if psKey, ok := c.sig.PsKeyMap[domain]; ok {
		return fmt.Sprintf("%s p_uin=o%d; p_skey=%s;", cookie, c.Uin, psKey)
	} else {
		return cookie
	}
}

func (c *QQClient) getCSRFToken() int {
	accu := 5381
	for _, b := range []byte(c.getSKey()) {
		accu = accu + (accu << 5) + int(b)
	}
	return 2147483647 & accu
}

func (c *QQClient) editMemberCard(groupCode, memberUin int64, card string) {
	_, _ = c.sendAndWait(c.buildEditGroupTagPacket(groupCode, memberUin, card))
}

func (c *QQClient) editMemberSpecialTitle(groupCode, memberUin int64, title string) {
	_, _ = c.sendAndWait(c.buildEditSpecialTitlePacket(groupCode, memberUin, title))
}

func (c *QQClient) setGroupAdmin(groupCode, memberUin int64, flag bool) {
	_, _ = c.sendAndWait(c.buildGroupAdminSetPacket(groupCode, memberUin, flag))
}

func (c *QQClient) updateGroupName(groupCode int64, newName string) {
	_, _ = c.sendAndWait(c.buildGroupNameUpdatePacket(groupCode, newName))
}

func (c *QQClient) groupMuteAll(groupCode int64, mute bool) {
	_, _ = c.sendAndWait(c.buildGroupMuteAllPacket(groupCode, mute))
}

func (c *QQClient) groupMute(groupCode, memberUin int64, time uint32) {
	_, _ = c.sendAndWait(c.buildGroupMutePacket(groupCode, memberUin, time))
}

func (c *QQClient) quitGroup(groupCode int64) {
	_, _ = c.sendAndWait(c.buildQuitGroupPacket(groupCode))
}

func (c *QQClient) KickGroupMembers(groupCode int64, msg string, block bool, memberUins ...int64) {
	_, _ = c.sendAndWait(c.buildGroupKickPacket(groupCode, msg, block, memberUins...))
}

func (g *GroupInfo) removeMember(uin int64) {
	g.Update(func(info *GroupInfo) {
		i := sort.Search(len(info.Members), func(i int) bool {
			return info.Members[i].Uin >= uin
		})
		if i >= len(info.Members) || info.Members[i].Uin != uin { // not found
			return
		}
		info.Members = append(info.Members[:i], info.Members[i+1:]...)
	})
}

func (c *QQClient) setGroupAnonymous(groupCode int64, enable bool) {
	_, _ = c.sendAndWait(c.buildSetGroupAnonymous(groupCode, enable))
}

// UpdateProfile 修改个人资料
func (c *QQClient) UpdateProfile(profile ProfileDetailUpdate) {
	_, _ = c.sendAndWait(c.buildUpdateProfileDetailPacket(profile))
}

func (c *QQClient) SetCustomServer(servers []netip.AddrPort) {
	c.servers = append(servers, c.servers...)
}
func (c *QQClient) unRegisterClient() error {
	_, err := c.sendAndWait(c.buildClientUnRegisterPacket())
	//	log.Infof("Unregister: %s", resp.(*trpc.UnRegisterResp).Message.Unwrap())
	return err
}

func (c *QQClient) registerClient() error {
	_, err := c.sendAndWait(c.buildClientRegisterPacket())
	if err == nil {
		c.Online.Store(true)
		c.firstLoginSucceed = true
	}
	return err
}

func (c *QQClient) nextSeq() uint16 {
	seq := c.SequenceId.Add(1)
	if seq > 1000000 {
		seq = int32(rand.Intn(100000)) + 60000
		c.SequenceId.Store(seq)
	}
	return uint16(seq)
}

func (c *QQClient) nextPacketSeq() int32 {
	return c.requestPacketRequestID.Add(2)
}

func (c *QQClient) nextGroupSeq() int32 {
	return c.groupSeq.Add(2)
}

func (c *QQClient) nextFriendSeq() int32 {
	return c.friendSeq.Add(1)
}

func (c *QQClient) nextQWebSeq() int64 {
	return c.qwebSeq.Add(1)
}

func (c *QQClient) nextHighwayApplySeq() int32 {
	return c.highwayApplyUpSeq.Add(2)
}

func (c *QQClient) doHeartbeat() {
	c.heartbeatEnabled = true
	times := 0
	for c.Online.Load() {
		if len(c.highwaySession.SsoAddr) == 0 {
			_, _ = c.sendAndWait(c.buildConnKeyRequestPacket()) // 高速通道不存在，请求获取高速通道地址。
		}
		time.Sleep(time.Second * 60)
		//time.Sleep(time.Second * 1)
		seq := c.nextSeq()
		req := network.Request{
			Type:        network.RequestTypeLogin,
			EncryptType: network.EncryptTypeNoEncrypt,
			SequenceID:  int32(seq),
			Uin:         c.Uin,
			CommandName: "Heartbeat.Alive",
			Body:        EmptyBytes,
		}
		packet := c.transport.PackPacket(&req)
		_, err := c.sendAndWait(seq, packet)
		if errors.Is(err, network.ErrConnectionClosed) {
			continue
		}
		times++
		if times == 4 {
			data, _ := proto.Marshal(&trpc.SsoHeartBeat{
				Unknown1: proto.Int32(1),
				Unknown2: &trpc.SsoHeartBeat_Unknown2{
					Unknown1: proto.Int32(1),
				},
				Unknown3: proto.Int32(149),
				Time:     proto.Int64(time.Now().Unix()),
			})
			_, err = c.sendAndWait(
				c.uniPacket("trpc.qq_new_tech.status_svc.StatusService.SsoHeartBeat", data),
			)
			if err != nil {
				log.Errorf("SsoHeartBeat Failed: %v", err)
				_ = c.unRegisterClient()
				_ = c.registerClient()
			}
		} else if times >= 5 {
			times = 0
		}
	}
	c.heartbeatEnabled = false
}
func (c *QQClient) GetRKeyString(rkType nt.RKeyType) string {
	rKey, _ := c.GetRKey()
	key := (*rKey)[rkType]
	if key == nil {
		return ""
	}
	return key.RKey
}
func (c *QQClient) GetDatabaseImageUrl(d *database.DatabaseImage) string {
	return d.GetDatabaseImageUrl(c.GetRKeyString(nt.RKeyType(d.BusinessType)))
}
func (c *QQClient) GetElementImageUrl(e *message.NewTechImageElement) string {
	if e.LegacyGroup != nil {
		if e.LegacyGroup.Url == "" {
			downLoadUrl, err := c.GetGroupImageDownloadUrl(e.LegacyGroup.FileId, c.GroupList[0].Code, e.LegacyGroup.Md5)
			if err != nil {
				log.Warnf("Failed to download image: %v", e)
			}
			return downLoadUrl
		}
		return e.LegacyGroup.Url
	} else if e.LegacyGuild != nil {
		return e.LegacyGuild.Url
	} else if e.LegacyFriend != nil {
		if e.LegacyFriend.Url == "" {
			i, err := c.sendAndWait(c.buildOffPicUpPacket(c.Uin, e.LegacyFriend.Md5, e.LegacyFriend.Size))
			if err != nil {
				log.Warn("couldn't get friend image url download address for decoding response")
				return ""
			}
			rsp := i.(*imageUploadResponse)
			if rsp.ResultCode != 0 {
				log.Warnf("couldn't get friend image url download address,code = %d", rsp.ResultCode)
				return ""
			}
			if rsp.IsExists {
				return "https://c2cpicdw.qpic.cn/offpic_new/0" + rsp.ResourceId + "/0?term=2"
			}
		}
		return e.LegacyFriend.Url
	}
	return e.DownloadUrl() + c.GetRKeyString(nt.RKeyType(e.BusinessType))
}
func (c *QQClient) GetElementVoiceUrl(e *message.NewTechVoiceElement) string {
	if e.Url != "" {
		return e.Url
	}
	var i any
	var err error
	if e.BusinessType == nt.BusinessFriendAudio {
		i, err = c.sendAndWait(c.buildNewTechCommonFriendVoiceDownPacket(e.FileUUID, c.Uin))
	} else {
		i, err = c.sendAndWait(c.buildNewTechCommonGroupVoiceDownPacket(e.FileUUID, c.GroupList[0].Code))
	}
	if err != nil {
		log.Warnf("Failed to download voice: %v", err)
		return ""
	}
	result := i.(nt.FileDownload).DownloadAccess
	return "https://" + result.Domain + result.FileUrl + result.RKeyUrlParam
}
