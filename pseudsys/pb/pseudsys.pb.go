// Code generated by protoc-gen-go.
// source: pseudsys/pb/pseudsys.proto
// DO NOT EDIT!

/*
Package pb is a generated protocol buffer package.

It is generated from these files:
	pseudsys/pb/pseudsys.proto

It has these top-level messages:
	CARequest
	CAResponse
	ProofRandData
	Cert
*/
package pb

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type CARequest struct {
	// Types that are valid to be assigned to Type:
	//	*CARequest_ProofRandData
	//	*CARequest_ProofData
	Type isCARequest_Type `protobuf_oneof:"type"`
}

func (m *CARequest) Reset()                    { *m = CARequest{} }
func (m *CARequest) String() string            { return proto.CompactTextString(m) }
func (*CARequest) ProtoMessage()               {}
func (*CARequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

type isCARequest_Type interface {
	isCARequest_Type()
}

type CARequest_ProofRandData struct {
	ProofRandData *ProofRandData `protobuf:"bytes,1,opt,name=proofRandData,oneof"`
}
type CARequest_ProofData struct {
	ProofData []byte `protobuf:"bytes,2,opt,name=proofData,proto3,oneof"`
}

func (*CARequest_ProofRandData) isCARequest_Type() {}
func (*CARequest_ProofData) isCARequest_Type()     {}

func (m *CARequest) GetType() isCARequest_Type {
	if m != nil {
		return m.Type
	}
	return nil
}

func (m *CARequest) GetProofRandData() *ProofRandData {
	if x, ok := m.GetType().(*CARequest_ProofRandData); ok {
		return x.ProofRandData
	}
	return nil
}

func (m *CARequest) GetProofData() []byte {
	if x, ok := m.GetType().(*CARequest_ProofData); ok {
		return x.ProofData
	}
	return nil
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*CARequest) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _CARequest_OneofMarshaler, _CARequest_OneofUnmarshaler, _CARequest_OneofSizer, []interface{}{
		(*CARequest_ProofRandData)(nil),
		(*CARequest_ProofData)(nil),
	}
}

func _CARequest_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*CARequest)
	// type
	switch x := m.Type.(type) {
	case *CARequest_ProofRandData:
		b.EncodeVarint(1<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.ProofRandData); err != nil {
			return err
		}
	case *CARequest_ProofData:
		b.EncodeVarint(2<<3 | proto.WireBytes)
		b.EncodeRawBytes(x.ProofData)
	case nil:
	default:
		return fmt.Errorf("CARequest.Type has unexpected type %T", x)
	}
	return nil
}

func _CARequest_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*CARequest)
	switch tag {
	case 1: // type.proofRandData
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(ProofRandData)
		err := b.DecodeMessage(msg)
		m.Type = &CARequest_ProofRandData{msg}
		return true, err
	case 2: // type.proofData
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeRawBytes(true)
		m.Type = &CARequest_ProofData{x}
		return true, err
	default:
		return false, nil
	}
}

func _CARequest_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*CARequest)
	// type
	switch x := m.Type.(type) {
	case *CARequest_ProofRandData:
		s := proto.Size(x.ProofRandData)
		n += proto.SizeVarint(1<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case *CARequest_ProofData:
		n += proto.SizeVarint(2<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(len(x.ProofData)))
		n += len(x.ProofData)
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

type CAResponse struct {
	// Types that are valid to be assigned to Type:
	//	*CAResponse_Challenge
	//	*CAResponse_Cert
	Type isCAResponse_Type `protobuf_oneof:"type"`
}

func (m *CAResponse) Reset()                    { *m = CAResponse{} }
func (m *CAResponse) String() string            { return proto.CompactTextString(m) }
func (*CAResponse) ProtoMessage()               {}
func (*CAResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

type isCAResponse_Type interface {
	isCAResponse_Type()
}

type CAResponse_Challenge struct {
	Challenge []byte `protobuf:"bytes,1,opt,name=challenge,proto3,oneof"`
}
type CAResponse_Cert struct {
	Cert *Cert `protobuf:"bytes,2,opt,name=cert,oneof"`
}

func (*CAResponse_Challenge) isCAResponse_Type() {}
func (*CAResponse_Cert) isCAResponse_Type()      {}

func (m *CAResponse) GetType() isCAResponse_Type {
	if m != nil {
		return m.Type
	}
	return nil
}

func (m *CAResponse) GetChallenge() []byte {
	if x, ok := m.GetType().(*CAResponse_Challenge); ok {
		return x.Challenge
	}
	return nil
}

func (m *CAResponse) GetCert() *Cert {
	if x, ok := m.GetType().(*CAResponse_Cert); ok {
		return x.Cert
	}
	return nil
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*CAResponse) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _CAResponse_OneofMarshaler, _CAResponse_OneofUnmarshaler, _CAResponse_OneofSizer, []interface{}{
		(*CAResponse_Challenge)(nil),
		(*CAResponse_Cert)(nil),
	}
}

func _CAResponse_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*CAResponse)
	// type
	switch x := m.Type.(type) {
	case *CAResponse_Challenge:
		b.EncodeVarint(1<<3 | proto.WireBytes)
		b.EncodeRawBytes(x.Challenge)
	case *CAResponse_Cert:
		b.EncodeVarint(2<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Cert); err != nil {
			return err
		}
	case nil:
	default:
		return fmt.Errorf("CAResponse.Type has unexpected type %T", x)
	}
	return nil
}

func _CAResponse_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*CAResponse)
	switch tag {
	case 1: // type.challenge
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeRawBytes(true)
		m.Type = &CAResponse_Challenge{x}
		return true, err
	case 2: // type.cert
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(Cert)
		err := b.DecodeMessage(msg)
		m.Type = &CAResponse_Cert{msg}
		return true, err
	default:
		return false, nil
	}
}

func _CAResponse_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*CAResponse)
	// type
	switch x := m.Type.(type) {
	case *CAResponse_Challenge:
		n += proto.SizeVarint(1<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(len(x.Challenge)))
		n += len(x.Challenge)
	case *CAResponse_Cert:
		s := proto.Size(x.Cert)
		n += proto.SizeVarint(2<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

// Random data for schnorr proof
type ProofRandData struct {
	X []byte `protobuf:"bytes,1,opt,name=X,proto3" json:"X,omitempty"`
	A []byte `protobuf:"bytes,2,opt,name=A,proto3" json:"A,omitempty"`
	B []byte `protobuf:"bytes,3,opt,name=B,proto3" json:"B,omitempty"`
}

func (m *ProofRandData) Reset()                    { *m = ProofRandData{} }
func (m *ProofRandData) String() string            { return proto.CompactTextString(m) }
func (*ProofRandData) ProtoMessage()               {}
func (*ProofRandData) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *ProofRandData) GetX() []byte {
	if m != nil {
		return m.X
	}
	return nil
}

func (m *ProofRandData) GetA() []byte {
	if m != nil {
		return m.A
	}
	return nil
}

func (m *ProofRandData) GetB() []byte {
	if m != nil {
		return m.B
	}
	return nil
}

type Cert struct {
	BlindedA []byte `protobuf:"bytes,1,opt,name=BlindedA,proto3" json:"BlindedA,omitempty"`
	BlindedB []byte `protobuf:"bytes,2,opt,name=BlindedB,proto3" json:"BlindedB,omitempty"`
	R        []byte `protobuf:"bytes,3,opt,name=R,proto3" json:"R,omitempty"`
	S        []byte `protobuf:"bytes,4,opt,name=S,proto3" json:"S,omitempty"`
}

func (m *Cert) Reset()                    { *m = Cert{} }
func (m *Cert) String() string            { return proto.CompactTextString(m) }
func (*Cert) ProtoMessage()               {}
func (*Cert) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *Cert) GetBlindedA() []byte {
	if m != nil {
		return m.BlindedA
	}
	return nil
}

func (m *Cert) GetBlindedB() []byte {
	if m != nil {
		return m.BlindedB
	}
	return nil
}

func (m *Cert) GetR() []byte {
	if m != nil {
		return m.R
	}
	return nil
}

func (m *Cert) GetS() []byte {
	if m != nil {
		return m.S
	}
	return nil
}

func init() {
	proto.RegisterType((*CARequest)(nil), "pb.CARequest")
	proto.RegisterType((*CAResponse)(nil), "pb.CAResponse")
	proto.RegisterType((*ProofRandData)(nil), "pb.ProofRandData")
	proto.RegisterType((*Cert)(nil), "pb.Cert")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for CA service

type CAClient interface {
	GenerateCertificate(ctx context.Context, opts ...grpc.CallOption) (CA_GenerateCertificateClient, error)
}

type cAClient struct {
	cc *grpc.ClientConn
}

func NewCAClient(cc *grpc.ClientConn) CAClient {
	return &cAClient{cc}
}

func (c *cAClient) GenerateCertificate(ctx context.Context, opts ...grpc.CallOption) (CA_GenerateCertificateClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_CA_serviceDesc.Streams[0], c.cc, "/pb.CA/GenerateCertificate", opts...)
	if err != nil {
		return nil, err
	}
	x := &cAGenerateCertificateClient{stream}
	return x, nil
}

type CA_GenerateCertificateClient interface {
	Send(*CARequest) error
	Recv() (*CAResponse, error)
	grpc.ClientStream
}

type cAGenerateCertificateClient struct {
	grpc.ClientStream
}

func (x *cAGenerateCertificateClient) Send(m *CARequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *cAGenerateCertificateClient) Recv() (*CAResponse, error) {
	m := new(CAResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// Server API for CA service

type CAServer interface {
	GenerateCertificate(CA_GenerateCertificateServer) error
}

func RegisterCAServer(s *grpc.Server, srv CAServer) {
	s.RegisterService(&_CA_serviceDesc, srv)
}

func _CA_GenerateCertificate_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(CAServer).GenerateCertificate(&cAGenerateCertificateServer{stream})
}

type CA_GenerateCertificateServer interface {
	Send(*CAResponse) error
	Recv() (*CARequest, error)
	grpc.ServerStream
}

type cAGenerateCertificateServer struct {
	grpc.ServerStream
}

func (x *cAGenerateCertificateServer) Send(m *CAResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *cAGenerateCertificateServer) Recv() (*CARequest, error) {
	m := new(CARequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

var _CA_serviceDesc = grpc.ServiceDesc{
	ServiceName: "pb.CA",
	HandlerType: (*CAServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "GenerateCertificate",
			Handler:       _CA_GenerateCertificate_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "pseudsys/pb/pseudsys.proto",
}

func init() { proto.RegisterFile("pseudsys/pb/pseudsys.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 285 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x54, 0x91, 0xbd, 0x4f, 0xc3, 0x30,
	0x10, 0xc5, 0xeb, 0x10, 0x55, 0xed, 0xb5, 0x45, 0xc2, 0x2c, 0x51, 0x06, 0x84, 0x32, 0x75, 0x4a,
	0x51, 0x98, 0x60, 0x22, 0x09, 0x12, 0x8c, 0xc8, 0x65, 0xa8, 0xd8, 0xf2, 0x71, 0x85, 0x48, 0x91,
	0x63, 0x62, 0x77, 0xe8, 0x7f, 0x8f, 0x3f, 0x9a, 0xd0, 0x6e, 0xfe, 0xdd, 0xdd, 0x7b, 0xf7, 0x72,
	0x81, 0x50, 0x48, 0x3c, 0xd4, 0xf2, 0x28, 0x37, 0xa2, 0xdc, 0x0c, 0xef, 0x58, 0xf4, 0x9d, 0xea,
	0xa8, 0x27, 0xca, 0x88, 0xc3, 0x3c, 0x4f, 0x19, 0xfe, 0x1e, 0x50, 0x2a, 0xfa, 0x04, 0x2b, 0xdd,
	0xe9, 0xf6, 0xac, 0xe0, 0xf5, 0x6b, 0xa1, 0x8a, 0x80, 0xdc, 0x93, 0xf5, 0x22, 0xb9, 0x89, 0x45,
	0x19, 0x7f, 0x9c, 0x37, 0xde, 0x27, 0xec, 0x72, 0x92, 0xde, 0xc1, 0xdc, 0x16, 0xac, 0xcc, 0xd3,
	0xb2, 0xa5, 0x9e, 0xf9, 0x2f, 0x65, 0x53, 0xf0, 0xd5, 0x51, 0x60, 0xf4, 0x09, 0x60, 0xf6, 0x49,
	0xd1, 0x71, 0x89, 0x46, 0x55, 0xfd, 0x14, 0x6d, 0x8b, 0xfc, 0x1b, 0xed, 0x32, 0xab, 0x1a, 0x4b,
	0xba, 0xef, 0x57, 0xd8, 0x2b, 0x6b, 0xb8, 0x48, 0x66, 0x26, 0x47, 0xae, 0x59, 0x0f, 0xd9, 0xfa,
	0xe8, 0xaa, 0x83, 0x5f, 0xe4, 0xa3, 0x4b, 0x20, 0x3b, 0x67, 0xc8, 0xc8, 0xce, 0x50, 0xea, 0x42,
	0x31, 0x92, 0x1a, 0xca, 0x82, 0x2b, 0x47, 0x59, 0xf4, 0x05, 0xbe, 0xb1, 0xa4, 0x21, 0xcc, 0xb2,
	0xb6, 0xe1, 0x35, 0xd6, 0xe9, 0x49, 0x38, 0xf2, 0x59, 0x2f, 0x3b, 0xd9, 0x8c, 0x6c, 0xdc, 0xd8,
	0xe0, 0xc6, 0x0c, 0x6d, 0x03, 0xdf, 0xd1, 0x36, 0x79, 0x01, 0x2f, 0x4f, 0xe9, 0x33, 0xdc, 0xbe,
	0x21, 0xc7, 0xbe, 0x50, 0x68, 0x36, 0x35, 0xfb, 0xa6, 0xd2, 0x4f, 0xba, 0xb2, 0x5f, 0x33, 0xdc,
	0x3e, 0xbc, 0x1e, 0xd0, 0x9d, 0x26, 0x9a, 0xac, 0xc9, 0x03, 0x29, 0xa7, 0xf6, 0x4f, 0x3d, 0xfe,
	0x05, 0x00, 0x00, 0xff, 0xff, 0xfb, 0x9f, 0x01, 0x0b, 0xc7, 0x01, 0x00, 0x00,
}
