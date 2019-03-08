/*
 * Copyright 2017 XLAB d.o.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package compat

import (
	"math/big"

	"github.com/emmyzkp/emmy/anauth/cl"
	"github.com/emmyzkp/emmy/anauth/cl/clpb"
)

type CLClient struct {
	*cl.Client
}

func NewCLClient(conn *Connection) *CLClient {
	return &CLClient{
		Client: cl.NewClient(conn.ClientConn),
	}
}

type CLPublicParams struct {
	PubKey *CLPubKey
	Config *CLParams
}

type Commitment struct {
	data []byte
}

type CLRevealedAttrs struct {
	attrs []string
}

func NewCLRevealedAttrs() *CLRevealedAttrs {
	return &CLRevealedAttrs{
		attrs: make([]string, 0),
	}
}

func (a *CLRevealedAttrs) Add(attr string) {
	a.attrs = append(a.attrs, attr)
}

func (c *CLClient) ProveCred(cm *CLCredManager, cred *CLCred,
	revealed *CLRevealedAttrs) (string, error) {
	sessKey, err := c.Client.ProveCredential(cm.CredManager,
		cred.getNativeType(), revealed.attrs)

	if err != nil {
		return "<INVALID>", err
	}

	return *sessKey, nil
}

type CLStringAttribute struct {
	*cl.StrAttr
}

type CLLongAttribute struct {
	*cl.Int64Attr
}

type CLRawCred struct {
	cred *cl.RawCred
}

func (c *CLRawCred) SetStringAttribute(name, val string) (*CLStringAttribute, error) {
	attr, err := c.cred.GetAttr(name)
	if err != nil {
		return nil, err
	}

	if err := attr.UpdateValue(val); err != nil {
		return nil, err
	}

	return &CLStringAttribute{
		StrAttr: attr.(*cl.StrAttr),
	}, nil
}

func (c *CLRawCred) SetLongAttribute(name string, val int) (*CLLongAttribute, error) {
	attr, err := c.cred.GetAttr(name)
	if err != nil {
		return nil, err
	}

	if err := attr.UpdateValue(val); err != nil {
		return nil, err
	}

	return &CLLongAttribute{
		Int64Attr: attr.(*cl.Int64Attr),
	}, nil
}

type CLCred struct {
	A   []byte
	E   []byte
	V11 []byte
}

func (c *CLCred) getNativeType() *cl.Cred {
	return &cl.Cred{
		A:   new(big.Int).SetBytes(c.A),
		E:   new(big.Int).SetBytes(c.E),
		V11: new(big.Int).SetBytes(c.V11),
	}
}

type PedersenParams struct {
	Group SchnorrGroup
	H     []byte
	a     []byte
}

type CLParams struct {
	*clpb.Params
}

type CLPubKey struct {
	*cl.PubKey
}

func (k *CLPubKey) GenerateMasterSecret() []byte {
	return k.PubKey.GenerateUserMasterSecret().Bytes()
}

type CLCredManager struct {
	*cl.CredManager
}

type CLCredManagerState struct {
	Nym                []byte
	V1                 []byte
	CredReqNonce       []byte
	PubKey             *CLPubKey
	Params             *CLParams
	Attrs              *CLAttrs
	CommitmentsOfAttrs []Commitment
}

// GetState returns a CLCredManagerState filled with
// current state of the CLCredManager. It can be used to restore
// a CLCredManager.
func (cm *CLCredManager) GetState() *CLCredManagerState {
	coa := make([]Commitment, len(cm.CommitmentsOfAttrs))
	for i, c := range cm.CommitmentsOfAttrs {
		coa[i] = Commitment{c.Bytes()}
	}

	return &CLCredManagerState{
		Nym:                cm.Nym.Bytes(),
		V1:                 cm.V1.Bytes(),
		CredReqNonce:       cm.CredReqNonce.Bytes(),
		PubKey:             &CLPubKey{cm.PubKey},
		Params:             &CLParams{cm.Params},
		CommitmentsOfAttrs: coa,
	}
}

// NewCLCredManager generates credential manager for the CL scheme.
// It accepts parameters for the CL scheme (these must match server-side
// configuration), server's public key, user's secret and attributes to
// manage.
func NewCLCredManager(params *CLParams, pk *CLPubKey,
	secret []byte, cred *CLRawCred) (*CLCredManager,
	error) {

	cm, err := cl.NewCredManager(params.Params,
		pk.PubKey,
		new(big.Int).SetBytes(secret),
		cred.cred)
	if err != nil {
		return nil, err
	}

	return &CLCredManager{
		CredManager: cm,
	}, nil
}

// RestoreCLCredManager establishes credential manager for the CL scheme.
// It is meant to be used to re-establish the credential manager after it
// has been previously created with NewCLCredManager.
func RestoreCLCredManager(state *CLCredManagerState, secret []byte,
	cred *CLRawCred) (*CLCredManager, error) {
	coa := make([]*big.Int, len(state.CommitmentsOfAttrs))
	for i, a := range state.CommitmentsOfAttrs {
		coa[i].SetBytes(a.data)
	}

	cm, err := cl.NewCredManagerFromExisting(
		new(big.Int).SetBytes(state.Nym),
		new(big.Int).SetBytes(state.V1),
		new(big.Int).SetBytes(state.CredReqNonce),
		state.Params.Params,
		state.PubKey.PubKey,
		new(big.Int).SetBytes(secret),
		cred.cred,
		coa,
	)
	if err != nil {
		return nil, err
	}

	return &CLCredManager{
		CredManager: cm,
	}, nil
}

func (c *CLClient) GetPublicParams() (*CLPublicParams, error) {
	cfg, pubKey, err := c.Client.GetPublicParams()
	if err != nil {
		return nil, err
	}

	return &CLPublicParams{
		PubKey: &CLPubKey{PubKey: pubKey},
		Config: &CLParams{Params: cfg},
	}, nil
}

func (c *CLClient) GetCredStructure() (*CLRawCred, error) {
	rc, err := c.Client.GetCredStructure()
	if err != nil {
		return nil, err
	}

	return &CLRawCred{
		cred: rc,
	}, nil
}

func (c *CLClient) IssueCred(cm *CLCredManager, regKey string) (*CLCred,
	error) {
	cred, err := c.Client.IssueCredential(cm.CredManager, regKey)
	if err != nil {
		return nil, err
	}

	return &CLCred{
		A:   cred.A.Bytes(),
		E:   cred.E.Bytes(),
		V11: cred.V11.Bytes(),
	}, nil
}
