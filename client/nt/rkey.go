package nt

type (
	RKeyType uint32
	RKeyMap  map[RKeyType]*RKeyInfo
)

const (
	BusinessGroupImage  = 20
	BusinessFriendImage = 10
	BusinessGroupVideo  = 21
	BusinessFriendVideo = 11
	BusinessGroupAudio  = 22
	BusinessFriendAudio = 12
)

const (
	FriendImageRKey RKeyType = BusinessFriendImage
	GroupImageRKey  RKeyType = BusinessGroupImage
)

type RKeyInfo struct {
	RKeyType   RKeyType
	RKey       string
	CreateTime uint64
	ExpireTime uint64
}
