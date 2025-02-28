// Code generated by protoc-gen-golite. DO NOT EDIT.
// source: pb/nt/oidb/oidbSvcTrpcTcp0xFE7_3/oidbSvcTrpcTcp0xfe7_3.proto

package oidbSvcTrpcTcp0xFE7_3

// Request message
type Request struct {
	GroupUin    int64         `protobuf:"varint,1,opt"`
	Field2      int64         `protobuf:"varint,2,opt"`
	Field3      int64         `protobuf:"varint,3,opt"`
	Body        *Body         `protobuf:"bytes,4,opt"`
	TargetsUser []*TargetUser `protobuf:"bytes,5,rep"`
	Token       string        `protobuf:"bytes,15,opt"`
}

// Body message
type Body struct {
	MemberName       bool `protobuf:"varint,10,opt"`
	MemberCard       bool `protobuf:"varint,11,opt"`
	Level            bool `protobuf:"varint,12,opt"`
	Field13          bool `protobuf:"varint,13,opt"`
	Field16          bool `protobuf:"varint,16,opt"`
	SpecialTitle     bool `protobuf:"varint,17,opt"`
	Field18          bool `protobuf:"varint,18,opt"`
	Field20          bool `protobuf:"varint,20,opt"`
	Field21          bool `protobuf:"varint,21,opt"`
	JoinTimestamp    bool `protobuf:"varint,100,opt"`
	LastMsgTimestamp bool `protobuf:"varint,101,opt"`
	ShutUpTimestamp  bool `protobuf:"varint,102,opt"`
	Field103         bool `protobuf:"varint,103,opt"`
	Field104         bool `protobuf:"varint,104,opt"`
	Field105         bool `protobuf:"varint,105,opt"`
	Field106         bool `protobuf:"varint,106,opt"`
	Permission       bool `protobuf:"varint,107,opt"`
	Field200         bool `protobuf:"varint,200,opt"`
	Field201         bool `protobuf:"varint,201,opt"`
	_                [0]func()
}

// TargetUser message
type TargetUser struct {
	Uid string `protobuf:"bytes,1,opt"`
	Uin int64  `protobuf:"varint,2,opt"`
	_   [0]func()
}

// Response message
type Response struct {
	GroupUin            int64     `protobuf:"varint,1,opt"`
	Members             []*Member `protobuf:"bytes,2,rep"`
	Field3              int64     `protobuf:"varint,3,opt"`
	MemberChangeSeq     int64     `protobuf:"varint,5,opt"`
	MemberCardChangeSeq int64     `protobuf:"varint,6,opt"`
	Token               string    `protobuf:"bytes,15,opt"`
}

// Member message
type Member struct {
	Uin              *Uin   `protobuf:"bytes,1,opt"`
	MemberName       string `protobuf:"bytes,10,opt"`
	MemberCard       *Card  `protobuf:"bytes,11,opt"`
	Level            *Level `protobuf:"bytes,12,opt"`
	SpecialTitle     string `protobuf:"bytes,17,opt"`
	JoinTimestamp    int32  `protobuf:"varint,100,opt"`
	LastMsgTimestamp int32  `protobuf:"varint,101,opt"`
	ShutUpTimestamp  int32  `protobuf:"varint,102,opt"`
	Permission       int32  `protobuf:"varint,107,opt"`
	_                [0]func()
}

// Uin message
type Uin struct {
	Uid string `protobuf:"bytes,2,opt"`
	Uin int64  `protobuf:"varint,4,opt"`
	_   [0]func()
}

// Card message
type Card struct {
	MemberCard string `protobuf:"bytes,2,opt"`
	_          [0]func()
}

// Level message
type Level struct {
	Level int32   `protobuf:"varint,2,opt"`
	Infos []int64 `protobuf:"varint,1,rep"`
}
