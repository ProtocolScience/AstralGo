// Code generated by protoc-gen-golite. DO NOT EDIT.
// source: pb/nt/oidb/oidbSvcTrpcTcp0xFE1_2/oidbSvcTrpcTcp0xfe1_2.proto

package oidbSvcTrpcTcp0xFE1_2

// Request message
type Req struct {
	Uid    string `protobuf:"bytes,1,opt"`
	Field2 int32  `protobuf:"varint,2,opt"`
	Keys   []*Key `protobuf:"bytes,3,rep"`
}

// Key message
type Key struct {
	Key int32 `protobuf:"varint,1,opt"`
	_   [0]func()
}

// Response message
type Response struct {
	Body *ResponseBody `protobuf:"bytes,1,opt"`
	_    [0]func()
}

// ResponseBody message
type ResponseBody struct {
	Uid string        `protobuf:"bytes,1,opt"`
	Map *ResponseList `protobuf:"bytes,2,opt"`
	Uin int64         `protobuf:"varint,3,opt"`
	_   [0]func()
}

// ResponseList message
type ResponseList struct {
	List1 []*ResponseList1 `protobuf:"bytes,1,rep"`
	List2 []*ResponseList2 `protobuf:"bytes,2,rep"`
}

// ResponseList1 message
type ResponseList1 struct {
	Ids    int32 `protobuf:"varint,1,opt"`
	Values int32 `protobuf:"varint,2,opt"`
	_      [0]func()
}

// ResponseList2 message
type ResponseList2 struct {
	Ids    int32  `protobuf:"varint,1,opt"`
	Values string `protobuf:"bytes,2,opt"`
	_      [0]func()
}
