// Code generated by protoc-gen-golite. DO NOT EDIT.
// source: pb/oidb/oidb0x88d.proto

package oidb

type D88DGroupHeadPortraitInfo struct {
	PicId *uint32 `protobuf:"varint,1,opt"`
}

func (x *D88DGroupHeadPortraitInfo) GetPicId() uint32 {
	if x != nil && x.PicId != nil {
		return *x.PicId
	}
	return 0
}

type D88DGroupHeadPortrait struct {
	PicCount            *uint32                      `protobuf:"varint,1,opt"`
	MsgInfo             []*D88DGroupHeadPortraitInfo `protobuf:"bytes,2,rep"`
	DefaultId           *uint32                      `protobuf:"varint,3,opt"`
	VerifyingPicCnt     *uint32                      `protobuf:"varint,4,opt"`
	MsgVerifyingPicInfo []*D88DGroupHeadPortraitInfo `protobuf:"bytes,5,rep"`
}

func (x *D88DGroupHeadPortrait) GetPicCount() uint32 {
	if x != nil && x.PicCount != nil {
		return *x.PicCount
	}
	return 0
}

func (x *D88DGroupHeadPortrait) GetDefaultId() uint32 {
	if x != nil && x.DefaultId != nil {
		return *x.DefaultId
	}
	return 0
}

func (x *D88DGroupHeadPortrait) GetVerifyingPicCnt() uint32 {
	if x != nil && x.VerifyingPicCnt != nil {
		return *x.VerifyingPicCnt
	}
	return 0
}

type D88DGroupExInfoOnly struct {
	TribeId          *uint32 `protobuf:"varint,1,opt"`
	MoneyForAddGroup *uint32 `protobuf:"varint,2,opt"`
}

func (x *D88DGroupExInfoOnly) GetTribeId() uint32 {
	if x != nil && x.TribeId != nil {
		return *x.TribeId
	}
	return 0
}

func (x *D88DGroupExInfoOnly) GetMoneyForAddGroup() uint32 {
	if x != nil && x.MoneyForAddGroup != nil {
		return *x.MoneyForAddGroup
	}
	return 0
}

type D88DGroupInfo struct {
	GroupOwner              *uint64                `protobuf:"varint,1,opt"`
	GroupCreateTime         *uint32                `protobuf:"varint,2,opt"`
	GroupFlag               *uint32                `protobuf:"varint,3,opt"`
	GroupFlagExt            *uint32                `protobuf:"varint,4,opt"`
	GroupMemberMaxNum       *uint32                `protobuf:"varint,5,opt"`
	GroupMemberNum          *uint32                `protobuf:"varint,6,opt"`
	GroupOption             *uint32                `protobuf:"varint,7,opt"`
	GroupClassExt           *uint32                `protobuf:"varint,8,opt"`
	GroupSpecialClass       *uint32                `protobuf:"varint,9,opt"`
	GroupLevel              *uint32                `protobuf:"varint,10,opt"`
	GroupFace               *uint32                `protobuf:"varint,11,opt"`
	GroupDefaultPage        *uint32                `protobuf:"varint,12,opt"`
	GroupInfoSeq            *uint32                `protobuf:"varint,13,opt"`
	GroupRoamingTime        *uint32                `protobuf:"varint,14,opt"`
	GroupName               []byte                 `protobuf:"bytes,15,opt"`
	GroupMemo               []byte                 `protobuf:"bytes,16,opt"`
	GroupFingerMemo         []byte                 `protobuf:"bytes,17,opt"`
	GroupClassText          []byte                 `protobuf:"bytes,18,opt"`
	GroupAllianceCode       []uint32               `protobuf:"varint,19,rep"`
	GroupExtraAadmNum       *uint32                `protobuf:"varint,20,opt"`
	GroupUin                *uint64                `protobuf:"varint,21,opt"`
	GroupCurMsgSeq          *uint32                `protobuf:"varint,22,opt"`
	GroupLastMsgTime        *uint32                `protobuf:"varint,23,opt"`
	GroupQuestion           []byte                 `protobuf:"bytes,24,opt"`
	GroupAnswer             []byte                 `protobuf:"bytes,25,opt"`
	GroupVisitorMaxNum      *uint32                `protobuf:"varint,26,opt"`
	GroupVisitorCurNum      *uint32                `protobuf:"varint,27,opt"`
	LevelNameSeq            *uint32                `protobuf:"varint,28,opt"`
	GroupAdminMaxNum        *uint32                `protobuf:"varint,29,opt"`
	GroupAioSkinTimestamp   *uint32                `protobuf:"varint,30,opt"`
	GroupBoardSkinTimestamp *uint32                `protobuf:"varint,31,opt"`
	GroupAioSkinUrl         []byte                 `protobuf:"bytes,32,opt"`
	GroupBoardSkinUrl       []byte                 `protobuf:"bytes,33,opt"`
	GroupCoverSkinTimestamp *uint32                `protobuf:"varint,34,opt"`
	GroupCoverSkinUrl       []byte                 `protobuf:"bytes,35,opt"`
	GroupGrade              *uint32                `protobuf:"varint,36,opt"`
	ActiveMemberNum         *uint32                `protobuf:"varint,37,opt"`
	CertificationType       *uint32                `protobuf:"varint,38,opt"`
	CertificationText       []byte                 `protobuf:"bytes,39,opt"`
	GroupRichFingerMemo     []byte                 `protobuf:"bytes,40,opt"`
	TagRecord               []*D88DTagRecord       `protobuf:"bytes,41,rep"`
	GroupGeoInfo            *D88DGroupGeoInfo      `protobuf:"bytes,42,opt"`
	HeadPortraitSeq         *uint32                `protobuf:"varint,43,opt"`
	MsgHeadPortrait         *D88DGroupHeadPortrait `protobuf:"bytes,44,opt"`
	ShutupTimestamp         *uint32                `protobuf:"varint,45,opt"`
	ShutupTimestampMe       *uint32                `protobuf:"varint,46,opt"`
	CreateSourceFlag        *uint32                `protobuf:"varint,47,opt"`
	CmduinMsgSeq            *uint32                `protobuf:"varint,48,opt"`
	CmduinJoinTime          *uint32                `protobuf:"varint,49,opt"`
	CmduinUinFlag           *uint32                `protobuf:"varint,50,opt"`
	CmduinFlagEx            *uint32                `protobuf:"varint,51,opt"`
	CmduinNewMobileFlag     *uint32                `protobuf:"varint,52,opt"`
	CmduinReadMsgSeq        *uint32                `protobuf:"varint,53,opt"`
	CmduinLastMsgTime       *uint32                `protobuf:"varint,54,opt"`
	GroupTypeFlag           *uint32                `protobuf:"varint,55,opt"`
	AppPrivilegeFlag        *uint32                `protobuf:"varint,56,opt"`
	StGroupExInfo           *D88DGroupExInfoOnly   `protobuf:"bytes,57,opt"`
	GroupSecLevel           *uint32                `protobuf:"varint,58,opt"`
	GroupSecLevelInfo       *uint32                `protobuf:"varint,59,opt"`
	CmduinPrivilege         *uint32                `protobuf:"varint,60,opt"`
	PoidInfo                []byte                 `protobuf:"bytes,61,opt"`
	CmduinFlagEx2           *uint32                `protobuf:"varint,62,opt"`
	ConfUin                 *uint64                `protobuf:"varint,63,opt"`
	ConfMaxMsgSeq           *uint32                `protobuf:"varint,64,opt"`
	ConfToGroupTime         *uint32                `protobuf:"varint,65,opt"`
	PasswordRedbagTime      *uint32                `protobuf:"varint,66,opt"`
	SubscriptionUin         *uint64                `protobuf:"varint,67,opt"`
	MemberListChangeSeq     *uint32                `protobuf:"varint,68,opt"`
	MembercardSeq           *uint32                `protobuf:"varint,69,opt"`
	RootId                  *uint64                `protobuf:"varint,70,opt"`
	ParentId                *uint64                `protobuf:"varint,71,opt"`
	TeamSeq                 *uint32                `protobuf:"varint,72,opt"`
	HistoryMsgBeginTime     *uint64                `protobuf:"varint,73,opt"`
	InviteNoAuthNumLimit    *uint64                `protobuf:"varint,74,opt"`
	CmduinHistoryMsgSeq     *uint32                `protobuf:"varint,75,opt"`
	CmduinJoinMsgSeq        *uint32                `protobuf:"varint,76,opt"`
	GroupFlagext3           *uint32                `protobuf:"varint,77,opt"`
	GroupOpenAppid          *uint32                `protobuf:"varint,78,opt"`
	IsConfGroup             *uint32                `protobuf:"varint,79,opt"`
	IsModifyConfGroupFace   *uint32                `protobuf:"varint,80,opt"`
	IsModifyConfGroupName   *uint32                `protobuf:"varint,81,opt"`
	NoFingerOpenFlag        *uint32                `protobuf:"varint,82,opt"`
	NoCodeFingerOpenFlag    *uint32                `protobuf:"varint,83,opt"`
}

func (x *D88DGroupInfo) GetGroupOwner() uint64 {
	if x != nil && x.GroupOwner != nil {
		return *x.GroupOwner
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupCreateTime() uint32 {
	if x != nil && x.GroupCreateTime != nil {
		return *x.GroupCreateTime
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupFlag() uint32 {
	if x != nil && x.GroupFlag != nil {
		return *x.GroupFlag
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupFlagExt() uint32 {
	if x != nil && x.GroupFlagExt != nil {
		return *x.GroupFlagExt
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupMemberMaxNum() uint32 {
	if x != nil && x.GroupMemberMaxNum != nil {
		return *x.GroupMemberMaxNum
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupMemberNum() uint32 {
	if x != nil && x.GroupMemberNum != nil {
		return *x.GroupMemberNum
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupOption() uint32 {
	if x != nil && x.GroupOption != nil {
		return *x.GroupOption
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupClassExt() uint32 {
	if x != nil && x.GroupClassExt != nil {
		return *x.GroupClassExt
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupSpecialClass() uint32 {
	if x != nil && x.GroupSpecialClass != nil {
		return *x.GroupSpecialClass
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupLevel() uint32 {
	if x != nil && x.GroupLevel != nil {
		return *x.GroupLevel
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupFace() uint32 {
	if x != nil && x.GroupFace != nil {
		return *x.GroupFace
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupDefaultPage() uint32 {
	if x != nil && x.GroupDefaultPage != nil {
		return *x.GroupDefaultPage
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupInfoSeq() uint32 {
	if x != nil && x.GroupInfoSeq != nil {
		return *x.GroupInfoSeq
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupRoamingTime() uint32 {
	if x != nil && x.GroupRoamingTime != nil {
		return *x.GroupRoamingTime
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupExtraAadmNum() uint32 {
	if x != nil && x.GroupExtraAadmNum != nil {
		return *x.GroupExtraAadmNum
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupUin() uint64 {
	if x != nil && x.GroupUin != nil {
		return *x.GroupUin
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupCurMsgSeq() uint32 {
	if x != nil && x.GroupCurMsgSeq != nil {
		return *x.GroupCurMsgSeq
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupLastMsgTime() uint32 {
	if x != nil && x.GroupLastMsgTime != nil {
		return *x.GroupLastMsgTime
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupVisitorMaxNum() uint32 {
	if x != nil && x.GroupVisitorMaxNum != nil {
		return *x.GroupVisitorMaxNum
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupVisitorCurNum() uint32 {
	if x != nil && x.GroupVisitorCurNum != nil {
		return *x.GroupVisitorCurNum
	}
	return 0
}

func (x *D88DGroupInfo) GetLevelNameSeq() uint32 {
	if x != nil && x.LevelNameSeq != nil {
		return *x.LevelNameSeq
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupAdminMaxNum() uint32 {
	if x != nil && x.GroupAdminMaxNum != nil {
		return *x.GroupAdminMaxNum
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupAioSkinTimestamp() uint32 {
	if x != nil && x.GroupAioSkinTimestamp != nil {
		return *x.GroupAioSkinTimestamp
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupBoardSkinTimestamp() uint32 {
	if x != nil && x.GroupBoardSkinTimestamp != nil {
		return *x.GroupBoardSkinTimestamp
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupCoverSkinTimestamp() uint32 {
	if x != nil && x.GroupCoverSkinTimestamp != nil {
		return *x.GroupCoverSkinTimestamp
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupGrade() uint32 {
	if x != nil && x.GroupGrade != nil {
		return *x.GroupGrade
	}
	return 0
}

func (x *D88DGroupInfo) GetActiveMemberNum() uint32 {
	if x != nil && x.ActiveMemberNum != nil {
		return *x.ActiveMemberNum
	}
	return 0
}

func (x *D88DGroupInfo) GetCertificationType() uint32 {
	if x != nil && x.CertificationType != nil {
		return *x.CertificationType
	}
	return 0
}

func (x *D88DGroupInfo) GetHeadPortraitSeq() uint32 {
	if x != nil && x.HeadPortraitSeq != nil {
		return *x.HeadPortraitSeq
	}
	return 0
}

func (x *D88DGroupInfo) GetShutupTimestamp() uint32 {
	if x != nil && x.ShutupTimestamp != nil {
		return *x.ShutupTimestamp
	}
	return 0
}

func (x *D88DGroupInfo) GetShutupTimestampMe() uint32 {
	if x != nil && x.ShutupTimestampMe != nil {
		return *x.ShutupTimestampMe
	}
	return 0
}

func (x *D88DGroupInfo) GetCreateSourceFlag() uint32 {
	if x != nil && x.CreateSourceFlag != nil {
		return *x.CreateSourceFlag
	}
	return 0
}

func (x *D88DGroupInfo) GetCmduinMsgSeq() uint32 {
	if x != nil && x.CmduinMsgSeq != nil {
		return *x.CmduinMsgSeq
	}
	return 0
}

func (x *D88DGroupInfo) GetCmduinJoinTime() uint32 {
	if x != nil && x.CmduinJoinTime != nil {
		return *x.CmduinJoinTime
	}
	return 0
}

func (x *D88DGroupInfo) GetCmduinUinFlag() uint32 {
	if x != nil && x.CmduinUinFlag != nil {
		return *x.CmduinUinFlag
	}
	return 0
}

func (x *D88DGroupInfo) GetCmduinFlagEx() uint32 {
	if x != nil && x.CmduinFlagEx != nil {
		return *x.CmduinFlagEx
	}
	return 0
}

func (x *D88DGroupInfo) GetCmduinNewMobileFlag() uint32 {
	if x != nil && x.CmduinNewMobileFlag != nil {
		return *x.CmduinNewMobileFlag
	}
	return 0
}

func (x *D88DGroupInfo) GetCmduinReadMsgSeq() uint32 {
	if x != nil && x.CmduinReadMsgSeq != nil {
		return *x.CmduinReadMsgSeq
	}
	return 0
}

func (x *D88DGroupInfo) GetCmduinLastMsgTime() uint32 {
	if x != nil && x.CmduinLastMsgTime != nil {
		return *x.CmduinLastMsgTime
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupTypeFlag() uint32 {
	if x != nil && x.GroupTypeFlag != nil {
		return *x.GroupTypeFlag
	}
	return 0
}

func (x *D88DGroupInfo) GetAppPrivilegeFlag() uint32 {
	if x != nil && x.AppPrivilegeFlag != nil {
		return *x.AppPrivilegeFlag
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupSecLevel() uint32 {
	if x != nil && x.GroupSecLevel != nil {
		return *x.GroupSecLevel
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupSecLevelInfo() uint32 {
	if x != nil && x.GroupSecLevelInfo != nil {
		return *x.GroupSecLevelInfo
	}
	return 0
}

func (x *D88DGroupInfo) GetCmduinPrivilege() uint32 {
	if x != nil && x.CmduinPrivilege != nil {
		return *x.CmduinPrivilege
	}
	return 0
}

func (x *D88DGroupInfo) GetCmduinFlagEx2() uint32 {
	if x != nil && x.CmduinFlagEx2 != nil {
		return *x.CmduinFlagEx2
	}
	return 0
}

func (x *D88DGroupInfo) GetConfUin() uint64 {
	if x != nil && x.ConfUin != nil {
		return *x.ConfUin
	}
	return 0
}

func (x *D88DGroupInfo) GetConfMaxMsgSeq() uint32 {
	if x != nil && x.ConfMaxMsgSeq != nil {
		return *x.ConfMaxMsgSeq
	}
	return 0
}

func (x *D88DGroupInfo) GetConfToGroupTime() uint32 {
	if x != nil && x.ConfToGroupTime != nil {
		return *x.ConfToGroupTime
	}
	return 0
}

func (x *D88DGroupInfo) GetPasswordRedbagTime() uint32 {
	if x != nil && x.PasswordRedbagTime != nil {
		return *x.PasswordRedbagTime
	}
	return 0
}

func (x *D88DGroupInfo) GetSubscriptionUin() uint64 {
	if x != nil && x.SubscriptionUin != nil {
		return *x.SubscriptionUin
	}
	return 0
}

func (x *D88DGroupInfo) GetMemberListChangeSeq() uint32 {
	if x != nil && x.MemberListChangeSeq != nil {
		return *x.MemberListChangeSeq
	}
	return 0
}

func (x *D88DGroupInfo) GetMembercardSeq() uint32 {
	if x != nil && x.MembercardSeq != nil {
		return *x.MembercardSeq
	}
	return 0
}

func (x *D88DGroupInfo) GetRootId() uint64 {
	if x != nil && x.RootId != nil {
		return *x.RootId
	}
	return 0
}

func (x *D88DGroupInfo) GetParentId() uint64 {
	if x != nil && x.ParentId != nil {
		return *x.ParentId
	}
	return 0
}

func (x *D88DGroupInfo) GetTeamSeq() uint32 {
	if x != nil && x.TeamSeq != nil {
		return *x.TeamSeq
	}
	return 0
}

func (x *D88DGroupInfo) GetHistoryMsgBeginTime() uint64 {
	if x != nil && x.HistoryMsgBeginTime != nil {
		return *x.HistoryMsgBeginTime
	}
	return 0
}

func (x *D88DGroupInfo) GetInviteNoAuthNumLimit() uint64 {
	if x != nil && x.InviteNoAuthNumLimit != nil {
		return *x.InviteNoAuthNumLimit
	}
	return 0
}

func (x *D88DGroupInfo) GetCmduinHistoryMsgSeq() uint32 {
	if x != nil && x.CmduinHistoryMsgSeq != nil {
		return *x.CmduinHistoryMsgSeq
	}
	return 0
}

func (x *D88DGroupInfo) GetCmduinJoinMsgSeq() uint32 {
	if x != nil && x.CmduinJoinMsgSeq != nil {
		return *x.CmduinJoinMsgSeq
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupFlagext3() uint32 {
	if x != nil && x.GroupFlagext3 != nil {
		return *x.GroupFlagext3
	}
	return 0
}

func (x *D88DGroupInfo) GetGroupOpenAppid() uint32 {
	if x != nil && x.GroupOpenAppid != nil {
		return *x.GroupOpenAppid
	}
	return 0
}

func (x *D88DGroupInfo) GetIsConfGroup() uint32 {
	if x != nil && x.IsConfGroup != nil {
		return *x.IsConfGroup
	}
	return 0
}

func (x *D88DGroupInfo) GetIsModifyConfGroupFace() uint32 {
	if x != nil && x.IsModifyConfGroupFace != nil {
		return *x.IsModifyConfGroupFace
	}
	return 0
}

func (x *D88DGroupInfo) GetIsModifyConfGroupName() uint32 {
	if x != nil && x.IsModifyConfGroupName != nil {
		return *x.IsModifyConfGroupName
	}
	return 0
}

func (x *D88DGroupInfo) GetNoFingerOpenFlag() uint32 {
	if x != nil && x.NoFingerOpenFlag != nil {
		return *x.NoFingerOpenFlag
	}
	return 0
}

func (x *D88DGroupInfo) GetNoCodeFingerOpenFlag() uint32 {
	if x != nil && x.NoCodeFingerOpenFlag != nil {
		return *x.NoCodeFingerOpenFlag
	}
	return 0
}

type ReqGroupInfo struct {
	GroupCode            *uint64        `protobuf:"varint,1,opt"`
	Stgroupinfo          *D88DGroupInfo `protobuf:"bytes,2,opt"`
	LastGetGroupNameTime *uint32        `protobuf:"varint,3,opt"`
}

func (x *ReqGroupInfo) GetGroupCode() uint64 {
	if x != nil && x.GroupCode != nil {
		return *x.GroupCode
	}
	return 0
}

func (x *ReqGroupInfo) GetLastGetGroupNameTime() uint32 {
	if x != nil && x.LastGetGroupNameTime != nil {
		return *x.LastGetGroupNameTime
	}
	return 0
}

type D88DReqBody struct {
	AppId           *uint32         `protobuf:"varint,1,opt"`
	ReqGroupInfo    []*ReqGroupInfo `protobuf:"bytes,2,rep"`
	PcClientVersion *uint32         `protobuf:"varint,3,opt"`
}

func (x *D88DReqBody) GetAppId() uint32 {
	if x != nil && x.AppId != nil {
		return *x.AppId
	}
	return 0
}

func (x *D88DReqBody) GetPcClientVersion() uint32 {
	if x != nil && x.PcClientVersion != nil {
		return *x.PcClientVersion
	}
	return 0
}

type RspGroupInfo struct {
	GroupCode *uint64        `protobuf:"varint,1,opt"`
	Result    *uint32        `protobuf:"varint,2,opt"`
	GroupInfo *D88DGroupInfo `protobuf:"bytes,3,opt"`
}

func (x *RspGroupInfo) GetGroupCode() uint64 {
	if x != nil && x.GroupCode != nil {
		return *x.GroupCode
	}
	return 0
}

func (x *RspGroupInfo) GetResult() uint32 {
	if x != nil && x.Result != nil {
		return *x.Result
	}
	return 0
}

type D88DRspBody struct {
	RspGroupInfo []*RspGroupInfo `protobuf:"bytes,1,rep"`
	StrErrorInfo []byte          `protobuf:"bytes,2,opt"`
}

type D88DTagRecord struct {
	FromUin   *uint64 `protobuf:"varint,1,opt"`
	GroupCode *uint64 `protobuf:"varint,2,opt"`
	TagId     []byte  `protobuf:"bytes,3,opt"`
	SetTime   *uint64 `protobuf:"varint,4,opt"`
	GoodNum   *uint32 `protobuf:"varint,5,opt"`
	BadNum    *uint32 `protobuf:"varint,6,opt"`
	TagLen    *uint32 `protobuf:"varint,7,opt"`
	TagValue  []byte  `protobuf:"bytes,8,opt"`
}

func (x *D88DTagRecord) GetFromUin() uint64 {
	if x != nil && x.FromUin != nil {
		return *x.FromUin
	}
	return 0
}

func (x *D88DTagRecord) GetGroupCode() uint64 {
	if x != nil && x.GroupCode != nil {
		return *x.GroupCode
	}
	return 0
}

func (x *D88DTagRecord) GetSetTime() uint64 {
	if x != nil && x.SetTime != nil {
		return *x.SetTime
	}
	return 0
}

func (x *D88DTagRecord) GetGoodNum() uint32 {
	if x != nil && x.GoodNum != nil {
		return *x.GoodNum
	}
	return 0
}

func (x *D88DTagRecord) GetBadNum() uint32 {
	if x != nil && x.BadNum != nil {
		return *x.BadNum
	}
	return 0
}

func (x *D88DTagRecord) GetTagLen() uint32 {
	if x != nil && x.TagLen != nil {
		return *x.TagLen
	}
	return 0
}

type D88DGroupGeoInfo struct {
	Owneruin   *uint64 `protobuf:"varint,1,opt"`
	Settime    *uint32 `protobuf:"varint,2,opt"`
	Cityid     *uint32 `protobuf:"varint,3,opt"`
	Longitude  *int64  `protobuf:"varint,4,opt"`
	Latitude   *int64  `protobuf:"varint,5,opt"`
	Geocontent []byte  `protobuf:"bytes,6,opt"`
	PoiId      *uint64 `protobuf:"varint,7,opt"`
}

func (x *D88DGroupGeoInfo) GetOwneruin() uint64 {
	if x != nil && x.Owneruin != nil {
		return *x.Owneruin
	}
	return 0
}

func (x *D88DGroupGeoInfo) GetSettime() uint32 {
	if x != nil && x.Settime != nil {
		return *x.Settime
	}
	return 0
}

func (x *D88DGroupGeoInfo) GetCityid() uint32 {
	if x != nil && x.Cityid != nil {
		return *x.Cityid
	}
	return 0
}

func (x *D88DGroupGeoInfo) GetLongitude() int64 {
	if x != nil && x.Longitude != nil {
		return *x.Longitude
	}
	return 0
}

func (x *D88DGroupGeoInfo) GetLatitude() int64 {
	if x != nil && x.Latitude != nil {
		return *x.Latitude
	}
	return 0
}

func (x *D88DGroupGeoInfo) GetPoiId() uint64 {
	if x != nil && x.PoiId != nil {
		return *x.PoiId
	}
	return 0
}
