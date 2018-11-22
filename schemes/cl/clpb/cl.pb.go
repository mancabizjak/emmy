// Code generated by protoc-gen-go.
// source: schemes/cl/clpb/cl.proto
// DO NOT EDIT!

/*
Package clpb is a generated protocol buffer package.

It is generated from these files:
	schemes/cl/clpb/cl.proto

It has these top-level messages:
	Request
	Response
	Empty
	CredIssueRequest
	Cred
	IssuedCred
	CredUpdateRequest
	CredProof
	FiatShamir
	FiatShamirAlsoNeg
*/
package clpb

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

type Request struct {
	// Types that are valid to be assigned to Type:
	//	*Request_Empty
	//	*Request_CredIssue
	//	*Request_CredProve
	Type isRequest_Type `protobuf_oneof:"type"`
}

func (m *Request) Reset()                    { *m = Request{} }
func (m *Request) String() string            { return proto.CompactTextString(m) }
func (*Request) ProtoMessage()               {}
func (*Request) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

type isRequest_Type interface {
	isRequest_Type()
}

type Request_Empty struct {
	Empty *Empty `protobuf:"bytes,1,opt,name=empty,oneof"`
}
type Request_CredIssue struct {
	CredIssue *CredIssueRequest `protobuf:"bytes,2,opt,name=credIssue,oneof"`
}
type Request_CredProve struct {
	CredProve *CredProof `protobuf:"bytes,3,opt,name=credProve,oneof"`
}

func (*Request_Empty) isRequest_Type()     {}
func (*Request_CredIssue) isRequest_Type() {}
func (*Request_CredProve) isRequest_Type() {}

func (m *Request) GetType() isRequest_Type {
	if m != nil {
		return m.Type
	}
	return nil
}

func (m *Request) GetEmpty() *Empty {
	if x, ok := m.GetType().(*Request_Empty); ok {
		return x.Empty
	}
	return nil
}

func (m *Request) GetCredIssue() *CredIssueRequest {
	if x, ok := m.GetType().(*Request_CredIssue); ok {
		return x.CredIssue
	}
	return nil
}

func (m *Request) GetCredProve() *CredProof {
	if x, ok := m.GetType().(*Request_CredProve); ok {
		return x.CredProve
	}
	return nil
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*Request) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _Request_OneofMarshaler, _Request_OneofUnmarshaler, _Request_OneofSizer, []interface{}{
		(*Request_Empty)(nil),
		(*Request_CredIssue)(nil),
		(*Request_CredProve)(nil),
	}
}

func _Request_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*Request)
	// type
	switch x := m.Type.(type) {
	case *Request_Empty:
		b.EncodeVarint(1<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Empty); err != nil {
			return err
		}
	case *Request_CredIssue:
		b.EncodeVarint(2<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.CredIssue); err != nil {
			return err
		}
	case *Request_CredProve:
		b.EncodeVarint(3<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.CredProve); err != nil {
			return err
		}
	case nil:
	default:
		return fmt.Errorf("Request.Type has unexpected type %T", x)
	}
	return nil
}

func _Request_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*Request)
	switch tag {
	case 1: // type.empty
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(Empty)
		err := b.DecodeMessage(msg)
		m.Type = &Request_Empty{msg}
		return true, err
	case 2: // type.credIssue
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(CredIssueRequest)
		err := b.DecodeMessage(msg)
		m.Type = &Request_CredIssue{msg}
		return true, err
	case 3: // type.credProve
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(CredProof)
		err := b.DecodeMessage(msg)
		m.Type = &Request_CredProve{msg}
		return true, err
	default:
		return false, nil
	}
}

func _Request_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*Request)
	// type
	switch x := m.Type.(type) {
	case *Request_Empty:
		s := proto.Size(x.Empty)
		n += proto.SizeVarint(1<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case *Request_CredIssue:
		s := proto.Size(x.CredIssue)
		n += proto.SizeVarint(2<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case *Request_CredProve:
		s := proto.Size(x.CredProve)
		n += proto.SizeVarint(3<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

type Response struct {
	// Types that are valid to be assigned to Type:
	//	*Response_Nonce
	//	*Response_IssuedCred
	//	*Response_Success
	Type isResponse_Type `protobuf_oneof:"type"`
}

func (m *Response) Reset()                    { *m = Response{} }
func (m *Response) String() string            { return proto.CompactTextString(m) }
func (*Response) ProtoMessage()               {}
func (*Response) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

type isResponse_Type interface {
	isResponse_Type()
}

type Response_Nonce struct {
	Nonce []byte `protobuf:"bytes,1,opt,name=nonce,proto3,oneof"`
}
type Response_IssuedCred struct {
	IssuedCred *IssuedCred `protobuf:"bytes,2,opt,name=issuedCred,oneof"`
}
type Response_Success struct {
	Success bool `protobuf:"varint,3,opt,name=success,oneof"`
}

func (*Response_Nonce) isResponse_Type()      {}
func (*Response_IssuedCred) isResponse_Type() {}
func (*Response_Success) isResponse_Type()    {}

func (m *Response) GetType() isResponse_Type {
	if m != nil {
		return m.Type
	}
	return nil
}

func (m *Response) GetNonce() []byte {
	if x, ok := m.GetType().(*Response_Nonce); ok {
		return x.Nonce
	}
	return nil
}

func (m *Response) GetIssuedCred() *IssuedCred {
	if x, ok := m.GetType().(*Response_IssuedCred); ok {
		return x.IssuedCred
	}
	return nil
}

func (m *Response) GetSuccess() bool {
	if x, ok := m.GetType().(*Response_Success); ok {
		return x.Success
	}
	return false
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*Response) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _Response_OneofMarshaler, _Response_OneofUnmarshaler, _Response_OneofSizer, []interface{}{
		(*Response_Nonce)(nil),
		(*Response_IssuedCred)(nil),
		(*Response_Success)(nil),
	}
}

func _Response_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*Response)
	// type
	switch x := m.Type.(type) {
	case *Response_Nonce:
		b.EncodeVarint(1<<3 | proto.WireBytes)
		b.EncodeRawBytes(x.Nonce)
	case *Response_IssuedCred:
		b.EncodeVarint(2<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.IssuedCred); err != nil {
			return err
		}
	case *Response_Success:
		t := uint64(0)
		if x.Success {
			t = 1
		}
		b.EncodeVarint(3<<3 | proto.WireVarint)
		b.EncodeVarint(t)
	case nil:
	default:
		return fmt.Errorf("Response.Type has unexpected type %T", x)
	}
	return nil
}

func _Response_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*Response)
	switch tag {
	case 1: // type.nonce
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeRawBytes(true)
		m.Type = &Response_Nonce{x}
		return true, err
	case 2: // type.issuedCred
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(IssuedCred)
		err := b.DecodeMessage(msg)
		m.Type = &Response_IssuedCred{msg}
		return true, err
	case 3: // type.success
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.Type = &Response_Success{x != 0}
		return true, err
	default:
		return false, nil
	}
}

func _Response_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*Response)
	// type
	switch x := m.Type.(type) {
	case *Response_Nonce:
		n += proto.SizeVarint(1<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(len(x.Nonce)))
		n += len(x.Nonce)
	case *Response_IssuedCred:
		s := proto.Size(x.IssuedCred)
		n += proto.SizeVarint(2<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case *Response_Success:
		n += proto.SizeVarint(3<<3 | proto.WireVarint)
		n += 1
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

type Empty struct {
}

func (m *Empty) Reset()                    { *m = Empty{} }
func (m *Empty) String() string            { return proto.CompactTextString(m) }
func (*Empty) ProtoMessage()               {}
func (*Empty) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

type CredIssueRequest struct {
	Nym                      []byte             `protobuf:"bytes,1,opt,name=Nym,proto3" json:"Nym,omitempty"`
	KnownAttrs               [][]byte           `protobuf:"bytes,2,rep,name=KnownAttrs,proto3" json:"KnownAttrs,omitempty"`
	CommitmentsOfAttrs       [][]byte           `protobuf:"bytes,3,rep,name=CommitmentsOfAttrs,proto3" json:"CommitmentsOfAttrs,omitempty"`
	NymProof                 *FiatShamir        `protobuf:"bytes,4,opt,name=NymProof" json:"NymProof,omitempty"`
	U                        []byte             `protobuf:"bytes,5,opt,name=U,proto3" json:"U,omitempty"`
	UProof                   *FiatShamirAlsoNeg `protobuf:"bytes,6,opt,name=UProof" json:"UProof,omitempty"`
	CommitmentsOfAttrsProofs []*FiatShamir      `protobuf:"bytes,7,rep,name=CommitmentsOfAttrsProofs" json:"CommitmentsOfAttrsProofs,omitempty"`
	Nonce                    []byte             `protobuf:"bytes,8,opt,name=Nonce,proto3" json:"Nonce,omitempty"`
}

func (m *CredIssueRequest) Reset()                    { *m = CredIssueRequest{} }
func (m *CredIssueRequest) String() string            { return proto.CompactTextString(m) }
func (*CredIssueRequest) ProtoMessage()               {}
func (*CredIssueRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *CredIssueRequest) GetNym() []byte {
	if m != nil {
		return m.Nym
	}
	return nil
}

func (m *CredIssueRequest) GetKnownAttrs() [][]byte {
	if m != nil {
		return m.KnownAttrs
	}
	return nil
}

func (m *CredIssueRequest) GetCommitmentsOfAttrs() [][]byte {
	if m != nil {
		return m.CommitmentsOfAttrs
	}
	return nil
}

func (m *CredIssueRequest) GetNymProof() *FiatShamir {
	if m != nil {
		return m.NymProof
	}
	return nil
}

func (m *CredIssueRequest) GetU() []byte {
	if m != nil {
		return m.U
	}
	return nil
}

func (m *CredIssueRequest) GetUProof() *FiatShamirAlsoNeg {
	if m != nil {
		return m.UProof
	}
	return nil
}

func (m *CredIssueRequest) GetCommitmentsOfAttrsProofs() []*FiatShamir {
	if m != nil {
		return m.CommitmentsOfAttrsProofs
	}
	return nil
}

func (m *CredIssueRequest) GetNonce() []byte {
	if m != nil {
		return m.Nonce
	}
	return nil
}

type Cred struct {
	A   []byte `protobuf:"bytes,1,opt,name=A,proto3" json:"A,omitempty"`
	E   []byte `protobuf:"bytes,2,opt,name=E,proto3" json:"E,omitempty"`
	V11 []byte `protobuf:"bytes,3,opt,name=V11,proto3" json:"V11,omitempty"`
}

func (m *Cred) Reset()                    { *m = Cred{} }
func (m *Cred) String() string            { return proto.CompactTextString(m) }
func (*Cred) ProtoMessage()               {}
func (*Cred) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *Cred) GetA() []byte {
	if m != nil {
		return m.A
	}
	return nil
}

func (m *Cred) GetE() []byte {
	if m != nil {
		return m.E
	}
	return nil
}

func (m *Cred) GetV11() []byte {
	if m != nil {
		return m.V11
	}
	return nil
}

type IssuedCred struct {
	Cred   *Cred              `protobuf:"bytes,1,opt,name=cred" json:"cred,omitempty"`
	AProof *FiatShamirAlsoNeg `protobuf:"bytes,2,opt,name=AProof" json:"AProof,omitempty"`
}

func (m *IssuedCred) Reset()                    { *m = IssuedCred{} }
func (m *IssuedCred) String() string            { return proto.CompactTextString(m) }
func (*IssuedCred) ProtoMessage()               {}
func (*IssuedCred) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

func (m *IssuedCred) GetCred() *Cred {
	if m != nil {
		return m.Cred
	}
	return nil
}

func (m *IssuedCred) GetAProof() *FiatShamirAlsoNeg {
	if m != nil {
		return m.AProof
	}
	return nil
}

type CredUpdateRequest struct {
	Nym           []byte   `protobuf:"bytes,1,opt,name=Nym,proto3" json:"Nym,omitempty"`
	Nonce         []byte   `protobuf:"bytes,2,opt,name=Nonce,proto3" json:"Nonce,omitempty"`
	NewKnownAttrs [][]byte `protobuf:"bytes,3,rep,name=NewKnownAttrs,proto3" json:"NewKnownAttrs,omitempty"`
}

func (m *CredUpdateRequest) Reset()                    { *m = CredUpdateRequest{} }
func (m *CredUpdateRequest) String() string            { return proto.CompactTextString(m) }
func (*CredUpdateRequest) ProtoMessage()               {}
func (*CredUpdateRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{6} }

func (m *CredUpdateRequest) GetNym() []byte {
	if m != nil {
		return m.Nym
	}
	return nil
}

func (m *CredUpdateRequest) GetNonce() []byte {
	if m != nil {
		return m.Nonce
	}
	return nil
}

func (m *CredUpdateRequest) GetNewKnownAttrs() [][]byte {
	if m != nil {
		return m.NewKnownAttrs
	}
	return nil
}

type CredProof struct {
	A                          []byte             `protobuf:"bytes,1,opt,name=A,proto3" json:"A,omitempty"`
	Proof                      *FiatShamirAlsoNeg `protobuf:"bytes,2,opt,name=Proof" json:"Proof,omitempty"`
	KnownAttrs                 [][]byte           `protobuf:"bytes,3,rep,name=KnownAttrs,proto3" json:"KnownAttrs,omitempty"`
	CommitmentsOfAttrs         [][]byte           `protobuf:"bytes,4,rep,name=CommitmentsOfAttrs,proto3" json:"CommitmentsOfAttrs,omitempty"`
	RevealedKnownAttrs         []int32            `protobuf:"varint,5,rep,packed,name=RevealedKnownAttrs" json:"RevealedKnownAttrs,omitempty"`
	RevealedCommitmentsOfAttrs []int32            `protobuf:"varint,6,rep,packed,name=RevealedCommitmentsOfAttrs" json:"RevealedCommitmentsOfAttrs,omitempty"`
}

func (m *CredProof) Reset()                    { *m = CredProof{} }
func (m *CredProof) String() string            { return proto.CompactTextString(m) }
func (*CredProof) ProtoMessage()               {}
func (*CredProof) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{7} }

func (m *CredProof) GetA() []byte {
	if m != nil {
		return m.A
	}
	return nil
}

func (m *CredProof) GetProof() *FiatShamirAlsoNeg {
	if m != nil {
		return m.Proof
	}
	return nil
}

func (m *CredProof) GetKnownAttrs() [][]byte {
	if m != nil {
		return m.KnownAttrs
	}
	return nil
}

func (m *CredProof) GetCommitmentsOfAttrs() [][]byte {
	if m != nil {
		return m.CommitmentsOfAttrs
	}
	return nil
}

func (m *CredProof) GetRevealedKnownAttrs() []int32 {
	if m != nil {
		return m.RevealedKnownAttrs
	}
	return nil
}

func (m *CredProof) GetRevealedCommitmentsOfAttrs() []int32 {
	if m != nil {
		return m.RevealedCommitmentsOfAttrs
	}
	return nil
}

type FiatShamir struct {
	// Used for example for SchnorrProof and RepresentationProof where challenge is constructed by prover
	// using hash function.
	// Note that here we don't have A and B as in SchnorrProofRandomData because usually when proving
	// the knowledge of X such that A^X = B, A is known beforehand (as part of public key).
	// So here ProofRandomData is actually only X.
	ProofRandomData []byte   `protobuf:"bytes,1,opt,name=ProofRandomData,proto3" json:"ProofRandomData,omitempty"`
	Challenge       []byte   `protobuf:"bytes,2,opt,name=Challenge,proto3" json:"Challenge,omitempty"`
	ProofData       [][]byte `protobuf:"bytes,3,rep,name=ProofData,proto3" json:"ProofData,omitempty"`
}

func (m *FiatShamir) Reset()                    { *m = FiatShamir{} }
func (m *FiatShamir) String() string            { return proto.CompactTextString(m) }
func (*FiatShamir) ProtoMessage()               {}
func (*FiatShamir) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{8} }

func (m *FiatShamir) GetProofRandomData() []byte {
	if m != nil {
		return m.ProofRandomData
	}
	return nil
}

func (m *FiatShamir) GetChallenge() []byte {
	if m != nil {
		return m.Challenge
	}
	return nil
}

func (m *FiatShamir) GetProofData() [][]byte {
	if m != nil {
		return m.ProofData
	}
	return nil
}

type FiatShamirAlsoNeg struct {
	// For proofs where proof data can be negative (see RepresentationProof).
	ProofRandomData []byte   `protobuf:"bytes,1,opt,name=ProofRandomData,proto3" json:"ProofRandomData,omitempty"`
	Challenge       []byte   `protobuf:"bytes,2,opt,name=Challenge,proto3" json:"Challenge,omitempty"`
	ProofData       []string `protobuf:"bytes,3,rep,name=ProofData" json:"ProofData,omitempty"`
}

func (m *FiatShamirAlsoNeg) Reset()                    { *m = FiatShamirAlsoNeg{} }
func (m *FiatShamirAlsoNeg) String() string            { return proto.CompactTextString(m) }
func (*FiatShamirAlsoNeg) ProtoMessage()               {}
func (*FiatShamirAlsoNeg) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{9} }

func (m *FiatShamirAlsoNeg) GetProofRandomData() []byte {
	if m != nil {
		return m.ProofRandomData
	}
	return nil
}

func (m *FiatShamirAlsoNeg) GetChallenge() []byte {
	if m != nil {
		return m.Challenge
	}
	return nil
}

func (m *FiatShamirAlsoNeg) GetProofData() []string {
	if m != nil {
		return m.ProofData
	}
	return nil
}

func init() {
	proto.RegisterType((*Request)(nil), "clpb.Request")
	proto.RegisterType((*Response)(nil), "clpb.Response")
	proto.RegisterType((*Empty)(nil), "clpb.Empty")
	proto.RegisterType((*CredIssueRequest)(nil), "clpb.CredIssueRequest")
	proto.RegisterType((*Cred)(nil), "clpb.Cred")
	proto.RegisterType((*IssuedCred)(nil), "clpb.IssuedCred")
	proto.RegisterType((*CredUpdateRequest)(nil), "clpb.CredUpdateRequest")
	proto.RegisterType((*CredProof)(nil), "clpb.CredProof")
	proto.RegisterType((*FiatShamir)(nil), "clpb.FiatShamir")
	proto.RegisterType((*FiatShamirAlsoNeg)(nil), "clpb.FiatShamirAlsoNeg")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for AnonCreds service

type AnonCredsClient interface {
	Issue(ctx context.Context, opts ...grpc.CallOption) (AnonCreds_IssueClient, error)
	Update(ctx context.Context, in *CredUpdateRequest, opts ...grpc.CallOption) (*IssuedCred, error)
	Prove(ctx context.Context, opts ...grpc.CallOption) (AnonCreds_ProveClient, error)
}

type anonCredsClient struct {
	cc *grpc.ClientConn
}

func NewAnonCredsClient(cc *grpc.ClientConn) AnonCredsClient {
	return &anonCredsClient{cc}
}

func (c *anonCredsClient) Issue(ctx context.Context, opts ...grpc.CallOption) (AnonCreds_IssueClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_AnonCreds_serviceDesc.Streams[0], c.cc, "/clpb.AnonCreds/Issue", opts...)
	if err != nil {
		return nil, err
	}
	x := &anonCredsIssueClient{stream}
	return x, nil
}

type AnonCreds_IssueClient interface {
	Send(*Request) error
	Recv() (*Response, error)
	grpc.ClientStream
}

type anonCredsIssueClient struct {
	grpc.ClientStream
}

func (x *anonCredsIssueClient) Send(m *Request) error {
	return x.ClientStream.SendMsg(m)
}

func (x *anonCredsIssueClient) Recv() (*Response, error) {
	m := new(Response)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *anonCredsClient) Update(ctx context.Context, in *CredUpdateRequest, opts ...grpc.CallOption) (*IssuedCred, error) {
	out := new(IssuedCred)
	err := grpc.Invoke(ctx, "/clpb.AnonCreds/Update", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *anonCredsClient) Prove(ctx context.Context, opts ...grpc.CallOption) (AnonCreds_ProveClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_AnonCreds_serviceDesc.Streams[1], c.cc, "/clpb.AnonCreds/Prove", opts...)
	if err != nil {
		return nil, err
	}
	x := &anonCredsProveClient{stream}
	return x, nil
}

type AnonCreds_ProveClient interface {
	Send(*Request) error
	Recv() (*Response, error)
	grpc.ClientStream
}

type anonCredsProveClient struct {
	grpc.ClientStream
}

func (x *anonCredsProveClient) Send(m *Request) error {
	return x.ClientStream.SendMsg(m)
}

func (x *anonCredsProveClient) Recv() (*Response, error) {
	m := new(Response)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// Server API for AnonCreds service

type AnonCredsServer interface {
	Issue(AnonCreds_IssueServer) error
	Update(context.Context, *CredUpdateRequest) (*IssuedCred, error)
	Prove(AnonCreds_ProveServer) error
}

func RegisterAnonCredsServer(s *grpc.Server, srv AnonCredsServer) {
	s.RegisterService(&_AnonCreds_serviceDesc, srv)
}

func _AnonCreds_Issue_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(AnonCredsServer).Issue(&anonCredsIssueServer{stream})
}

type AnonCreds_IssueServer interface {
	Send(*Response) error
	Recv() (*Request, error)
	grpc.ServerStream
}

type anonCredsIssueServer struct {
	grpc.ServerStream
}

func (x *anonCredsIssueServer) Send(m *Response) error {
	return x.ServerStream.SendMsg(m)
}

func (x *anonCredsIssueServer) Recv() (*Request, error) {
	m := new(Request)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _AnonCreds_Update_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CredUpdateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AnonCredsServer).Update(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/clpb.AnonCreds/Update",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AnonCredsServer).Update(ctx, req.(*CredUpdateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AnonCreds_Prove_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(AnonCredsServer).Prove(&anonCredsProveServer{stream})
}

type AnonCreds_ProveServer interface {
	Send(*Response) error
	Recv() (*Request, error)
	grpc.ServerStream
}

type anonCredsProveServer struct {
	grpc.ServerStream
}

func (x *anonCredsProveServer) Send(m *Response) error {
	return x.ServerStream.SendMsg(m)
}

func (x *anonCredsProveServer) Recv() (*Request, error) {
	m := new(Request)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

var _AnonCreds_serviceDesc = grpc.ServiceDesc{
	ServiceName: "clpb.AnonCreds",
	HandlerType: (*AnonCredsServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Update",
			Handler:    _AnonCreds_Update_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Issue",
			Handler:       _AnonCreds_Issue_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
		{
			StreamName:    "Prove",
			Handler:       _AnonCreds_Prove_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "schemes/cl/clpb/cl.proto",
}

func init() { proto.RegisterFile("schemes/cl/clpb/cl.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 659 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0xb4, 0x55, 0xdb, 0x6e, 0xd3, 0x4c,
	0x10, 0x8e, 0x13, 0x3b, 0x87, 0x69, 0xfb, 0x37, 0x5d, 0xfd, 0x6a, 0xad, 0x08, 0x21, 0x64, 0xb8,
	0x88, 0x04, 0x4d, 0x68, 0x38, 0x5c, 0x22, 0xb9, 0x25, 0x88, 0x0a, 0x14, 0x90, 0x51, 0xb8, 0x40,
	0xe2, 0xc2, 0x71, 0xb6, 0x49, 0x44, 0x7c, 0xc0, 0xbb, 0x69, 0x95, 0x3e, 0x01, 0x4f, 0x01, 0x4f,
	0xc3, 0x7b, 0xb1, 0x3b, 0x6b, 0xc7, 0xae, 0x93, 0x96, 0xdc, 0x20, 0x45, 0x91, 0x77, 0xe6, 0xfb,
	0x66, 0xbe, 0x39, 0x78, 0x0d, 0x26, 0xf3, 0xa6, 0xd4, 0xa7, 0xac, 0xeb, 0xcd, 0xc5, 0x2f, 0x1a,
	0x89, 0xbf, 0x4e, 0x14, 0x87, 0x3c, 0x24, 0xba, 0x3c, 0x5a, 0xbf, 0x34, 0xa8, 0x39, 0xf4, 0xfb,
	0x82, 0x32, 0x4e, 0x1e, 0x82, 0x41, 0xfd, 0x88, 0x2f, 0x4d, 0xed, 0x81, 0xd6, 0xde, 0xe9, 0xed,
	0x74, 0x24, 0xa2, 0xd3, 0x97, 0xa6, 0xb7, 0x25, 0x47, 0xf9, 0xc8, 0x4b, 0x68, 0x78, 0x31, 0x1d,
	0x9f, 0x33, 0xb6, 0xa0, 0x66, 0x19, 0x81, 0x87, 0x0a, 0x78, 0x96, 0x9a, 0x93, 0x78, 0x82, 0x93,
	0x41, 0x49, 0x57, 0xf1, 0x3e, 0xc6, 0xe1, 0x25, 0x35, 0x2b, 0xc8, 0xdb, 0xcf, 0x78, 0xc2, 0x1c,
	0x5e, 0xa4, 0x04, 0xc4, 0x9c, 0x56, 0x41, 0xe7, 0xcb, 0x88, 0x5a, 0xd7, 0x50, 0x77, 0x28, 0x8b,
	0xc2, 0x80, 0x51, 0x72, 0x08, 0x46, 0x10, 0x06, 0x1e, 0x45, 0x85, 0xbb, 0x52, 0x14, 0x1e, 0x49,
	0x0f, 0x60, 0x26, 0xb3, 0x8c, 0x65, 0xac, 0x44, 0x55, 0x53, 0x45, 0x3f, 0x5f, 0xd9, 0x05, 0x3c,
	0x87, 0x22, 0x2d, 0xa8, 0xb1, 0x85, 0xe7, 0x51, 0xc6, 0x50, 0x4e, 0x5d, 0xb8, 0x53, 0xc3, 0x2a,
	0x77, 0x0d, 0x0c, 0x2c, 0xdf, 0xfa, 0x5d, 0x86, 0x66, 0xb1, 0x3e, 0xd2, 0x84, 0xca, 0x60, 0xe9,
	0x2b, 0x2d, 0x8e, 0x7c, 0x24, 0xf7, 0x01, 0xde, 0x05, 0xe1, 0x55, 0x60, 0x73, 0x1e, 0x33, 0xa1,
	0xa3, 0x22, 0x1c, 0x39, 0x0b, 0xe9, 0x00, 0x39, 0x0b, 0x7d, 0x7f, 0xc6, 0x7d, 0x1a, 0x70, 0xf6,
	0xe1, 0x42, 0xe1, 0x2a, 0x88, 0xdb, 0xe0, 0x21, 0x4f, 0xa0, 0x2e, 0xc2, 0x62, 0x73, 0x4c, 0x3d,
	0x5f, 0xd5, 0x9b, 0x99, 0xcb, 0x3f, 0x4d, 0x5d, 0x7f, 0x16, 0x3b, 0x2b, 0x04, 0xd9, 0x05, 0x6d,
	0x68, 0x1a, 0xa8, 0x46, 0x1b, 0x8a, 0x86, 0x57, 0x87, 0x8a, 0x59, 0x45, 0xe6, 0x51, 0x91, 0x69,
	0xcf, 0x59, 0x38, 0xa0, 0x13, 0x27, 0x81, 0x91, 0xf7, 0x60, 0xae, 0x4b, 0x40, 0x17, 0x33, 0x6b,
	0x42, 0xe2, 0xa6, 0xe4, 0xb7, 0x32, 0xc8, 0xff, 0x60, 0x0c, 0x70, 0x54, 0x75, 0x14, 0xa4, 0x0e,
	0xd6, 0x73, 0xd0, 0xb1, 0xf9, 0x42, 0xaa, 0x9d, 0x34, 0x4e, 0xb3, 0xe5, 0xa9, 0x8f, 0x53, 0x13,
	0xa7, 0xbe, 0x6c, 0xeb, 0xe7, 0x93, 0x13, 0x1c, 0x8a, 0x68, 0xab, 0x78, 0xb4, 0xbe, 0x02, 0x64,
	0x63, 0x14, 0x4d, 0xd6, 0xe5, 0x96, 0x24, 0x5b, 0x0a, 0xd9, 0x12, 0x39, 0x68, 0x97, 0x85, 0xdb,
	0xaa, 0xf0, 0xf2, 0x5f, 0x0a, 0x57, 0x30, 0xcb, 0x85, 0x03, 0x49, 0x1f, 0x46, 0x63, 0x97, 0xdf,
	0x31, 0xdc, 0x55, 0x45, 0xe5, 0x5c, 0x45, 0xe4, 0x11, 0xec, 0x0d, 0xe8, 0x55, 0x6e, 0xea, 0x6a,
	0x9a, 0x37, 0x8d, 0xd6, 0x8f, 0x32, 0x34, 0x56, 0x7b, 0x5e, 0xa8, 0xfe, 0x18, 0x8c, 0xad, 0xe4,
	0x2a, 0x54, 0x61, 0xc7, 0x2a, 0x5b, 0xee, 0x98, 0x7e, 0xeb, 0x8e, 0x09, 0xbc, 0x43, 0x2f, 0xa9,
	0x3b, 0xa7, 0xe3, 0x5c, 0x5c, 0x43, 0xe0, 0x0d, 0x67, 0x83, 0x87, 0xbc, 0x82, 0x56, 0x6a, 0xdd,
	0x90, 0xa7, 0x8a, 0xbc, 0x3b, 0x10, 0x56, 0x0c, 0x90, 0xd5, 0x46, 0xda, 0xb0, 0x8f, 0x65, 0x39,
	0x6e, 0x30, 0x0e, 0xfd, 0xd7, 0x2e, 0x77, 0x93, 0xc6, 0x14, 0xcd, 0xe4, 0x9e, 0xe8, 0xe0, 0xd4,
	0x9d, 0xcf, 0x69, 0x30, 0x49, 0x47, 0x90, 0x19, 0xa4, 0x17, 0x09, 0x18, 0x41, 0x35, 0x25, 0x33,
	0x58, 0x4b, 0x38, 0x58, 0xeb, 0xe7, 0xbf, 0x4b, 0xdd, 0xc8, 0xa5, 0xee, 0xfd, 0xd4, 0xa0, 0x61,
	0x8b, 0x5b, 0x4a, 0x4e, 0x5f, 0xbe, 0xd0, 0x86, 0xba, 0x0e, 0xf7, 0xd4, 0x94, 0x93, 0x6d, 0x6b,
	0xfd, 0x97, 0x1e, 0xd5, 0x45, 0x67, 0x95, 0xda, 0xda, 0x53, 0x8d, 0xbc, 0x10, 0xaf, 0x30, 0x2e,
	0x25, 0x39, 0xca, 0xb6, 0xfc, 0xc6, 0x9a, 0xb6, 0xd6, 0x6e, 0x39, 0xab, 0x24, 0x93, 0xe0, 0x15,
	0xba, 0x55, 0x92, 0xd3, 0xe3, 0x2f, 0x8f, 0x27, 0x33, 0x3e, 0x5d, 0x8c, 0x3a, 0x5e, 0xe8, 0x77,
	0xa9, 0xef, 0x2f, 0xaf, 0xbf, 0x45, 0x5d, 0x57, 0x48, 0x76, 0x17, 0x7c, 0xda, 0x2d, 0x7c, 0x3f,
	0x46, 0x55, 0xfc, 0x7a, 0x3c, 0xfb, 0x13, 0x00, 0x00, 0xff, 0xff, 0xbd, 0x3f, 0xc6, 0x83, 0x59,
	0x06, 0x00, 0x00,
}
