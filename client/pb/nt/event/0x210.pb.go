// Code generated by protoc-gen-golite. DO NOT EDIT.
// source: pb/nt/event/0x210.proto

package event

type NewFriend struct {
	Field1 uint32         `protobuf:"varint,1,opt"`
	Info   *NewFriendInfo `protobuf:"bytes,2,opt"`
	_      [0]func()
}

type NewFriendInfo struct {
	Uid      string `protobuf:"bytes,1,opt"`
	Field2   uint32 `protobuf:"varint,2,opt"`
	Time     uint32 `protobuf:"fixed32,3,opt"`
	Message  string `protobuf:"bytes,4,opt"`
	NickName string `protobuf:"bytes,5,opt"`
	Field6   uint32 `protobuf:"varint,6,opt"`
	Field7   uint32 `protobuf:"varint,7,opt"`
	ToUid    string `protobuf:"bytes,9,opt"`
	_        [0]func()
}
