// Code generated by protoc-gen-golite. DO NOT EDIT.
// source: pb/nt/oidb/oidbSvcTrpcTcp0x9082/oidbSvcTrpcTcp0x9082_1.proto

package oidbSvcTrpcTcp0x9082

type Reaction struct {
	GroupId int64  `protobuf:"varint,2,opt"`
	Seq     int32  `protobuf:"varint,3,opt"`
	IconId  string `protobuf:"bytes,4,opt"`
	Type    int32  `protobuf:"varint,5,opt"` // 2=emoji 1=qq self icon
	_       [0]func()
}
