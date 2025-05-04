package client

type (
	FriendRelation struct {
		FriendAddInfo   *FriendAddInfo
		CommonGroupInfo *CommonGroupInfoList
	}

	FriendAddInfo struct {
		Reason string
	}

	CommonGroupInfoList struct {
		CommonGroupInfo  []*CommonGroupInfo
		SpecialGroupInfo *CommonGroupInfo
		Reason           string
	}

	CommonGroupInfo struct {
		GroupUin  int64
		GroupId   int64
		GroupName string
		Timestamp int64
	}
)
