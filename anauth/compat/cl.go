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

	"github.com/emmyzkp/crypto/pedersen"

	"github.com/emmyzkp/emmy/anauth/cl"
)

type CLClient struct {
	*cl.Client
}

func NewCLClient(conn *Connection) *CLClient {
	return &CLClient{
		Client: cl.NewClient(conn.ClientConn),
	}
}

func (c *CLClient) IssueCred(cm CLCredManager, regKey string) (*CLCred, error) {
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

func (c *CLClient) ProveCred(cm CLCredManager, cred CLCred,
	known [][]byte, revealedI, revealedCommI []int) (string,
	error) {
	knownAttrs := make([]*big.Int, len(known))
	for i, r := range known {
		knownAttrs[i].SetBytes(r)
	}

	sessKey, err := c.Client.ProveCredential(cm.CredManager,
		cred.getNativeType(),
		knownAttrs, revealedI, revealedCommI)

	if err != nil {
		return "<INVALID>", err
	}

	return *sessKey, nil
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
	*cl.Params
}

func GetCLDefaultParams() *CLParams {
	return &CLParams{
		Params: cl.GetDefaultParamSizes(),
	}
}

type CLOrgPubKey struct {
	N              []byte
	S              []byte
	Z              []byte
	RsKnown        [][]byte       // UNSUPPORTED
	RsCommitted    [][]byte       // UNSUPPORTED
	RsHidden       [][]byte       // UNSUPPORTED
	PedersenParams PedersenParams // UNSUPPORTED?
	N1             []byte
	G              []byte
	H              []byte
}

func (k *CLOrgPubKey) GetUserMasterSecret() ([]byte, error) {
	// FIXME avoid conversion, do wrapping instead
	key, err := k.getNativeType()
	if err != nil {
		return nil, err
	}
	return key.GenerateUserMasterSecret().Bytes(), nil
}

func (k *CLOrgPubKey) getNativeType() (*cl.PubKey, error) {
	rsKnown := make([]*big.Int, len(k.RsKnown))
	for i, r := range k.RsKnown {
		rsKnown[i].SetBytes(r)
	}
	rsCommitted := make([]*big.Int, len(k.RsCommitted))
	for i, r := range k.RsCommitted {
		rsCommitted[i].SetBytes(r)
	}
	rsHidden := make([]*big.Int, len(k.RsHidden))
	for i, r := range k.RsHidden {
		rsHidden[i].SetBytes(r)
	}

	group, err := k.PedersenParams.Group.toNativeType()
	if err != nil {
		return nil, err
	}

	pp := pedersen.NewParams(
		group,
		new(big.Int).SetBytes(k.PedersenParams.H),
		new(big.Int).SetBytes(k.PedersenParams.a))

	return &cl.PubKey{
		N:              new(big.Int).SetBytes(k.N),
		S:              new(big.Int).SetBytes(k.S),
		Z:              new(big.Int).SetBytes(k.Z),
		RsKnown:        rsKnown,
		RsCommitted:    rsCommitted,
		RsHidden:       rsHidden,
		PedersenParams: pp,
		N1:             new(big.Int).SetBytes(k.N1),
		G:              new(big.Int).SetBytes(k.G),
		H:              new(big.Int).SetBytes(k.H),
	}, nil
}

type CLCredManager struct {
	*cl.CredManager
}

type CLAttrs struct {
	Known     [][]byte // UNSUPPORTED
	Hidden    [][]byte // UNSUPPORTED
	Committed [][]byte // UNSUPPORTED
}

func (a *CLAttrs) getNativeType() *cl.Attrs {
	known := make([]*big.Int, len(a.Known))
	for i, r := range a.Known {
		known[i].SetBytes(r)
	}

	hidden := make([]*big.Int, len(a.Hidden))
	for i, r := range a.Hidden {
		hidden[i].SetBytes(r)
	}

	committed := make([]*big.Int, len(a.Committed))
	for i, r := range a.Committed {
		committed[i].SetBytes(r)
	}

	return cl.NewAttrs(known, hidden, committed)
}

func NewCLCredManager(params *CLParams, pk *CLOrgPubKey,
	secret []byte, attrs *CLAttrs) (*CLCredManager,
	error) {
	pubKey, err := pk.getNativeType()
	if err != nil {
		return nil, err
	}

	cm, err := cl.NewCredManager(params.Params,
		pubKey,
		new(big.Int).SetBytes(secret),
		attrs.getNativeType())
	if err != nil {
		return nil, err
	}

	return &CLCredManager{
		CredManager: cm,
	}, nil
}

func RestoreCLCredManager(params CLParams, pk *CLOrgPubKey, secret,
	nym, v1, nonce []byte, commitmentsOfAttrs [][]byte, attrs *CLAttrs) (*CLCredManager, error) {
	pubKey, err := pk.getNativeType()
	if err != nil {
		return nil, err
	}

	coa := make([]*big.Int, len(commitmentsOfAttrs))
	for i, a := range commitmentsOfAttrs {
		coa[i].SetBytes(a)
	}

	cm, err := cl.NewCredManagerFromExisting(
		new(big.Int).SetBytes(nym),
		new(big.Int).SetBytes(v1),
		new(big.Int).SetBytes(nonce),
		params.Params,
		pubKey,
		new(big.Int).SetBytes(secret),
		attrs.getNativeType(),
		coa,
	)
	if err != nil {
		return nil, err
	}

	return &CLCredManager{
		CredManager: cm,
	}, nil
}
