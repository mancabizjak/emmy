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

package cl

import (
	"fmt"

	"math/big"

	"github.com/xlab-si/emmy/cl/pb"
	"github.com/xlab-si/emmy/crypto/df"
	"github.com/xlab-si/emmy/crypto/qr"
	"github.com/xlab-si/emmy/crypto/schnorr"
	"github.com/xlab-si/emmy/proto"
	"golang.org/x/net/context"
)

type Server struct{}

func fromByteSlices(s [][]byte) []*big.Int {
	res := make([]*big.Int, len(s))
	for i, si := range s {
		res[i] = new(big.Int).SetBytes(si)
	}

	return res
}

func fromStringSlices(s []string) ([]*big.Int, error) {
	res := make([]*big.Int, len(s))
	for i, si := range s {
		x, ok := new(big.Int).SetString(si, 10)
		if !ok {
			return nil, fmt.Errorf("error when initializing big.Int from string")
		}
		res[i] = x
	}

	return res, nil
}

func (s *Server) Issue(stream pb.AnonCreds_IssueServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	org, err := LoadOrg("organization1", "../client/testdata/clSecKey.gob", "../client/testdata/clPubKey.gob")
	if err != nil {
		return err
	}

	nonce := org.GetCredIssueNonce()
	resp := &pb.Response{
		Type: &pb.Response_Nonce{
			Nonce: &proto.BigInt{
				X1: nonce.Bytes(),
			},
		},
	}

	if err := stream.Send(resp); err != nil {
		return err
	}

	req, err = stream.Recv()
	if err != nil {
		return err
	}

	reqIssue := req.GetCredIssue()

	nymProof := schnorr.NewProof(
		new(big.Int).SetBytes(reqIssue.NymProof.ProofRandomData),
		new(big.Int).SetBytes(reqIssue.NymProof.Challenge),
		fromByteSlices(reqIssue.NymProof.ProofData),
	)

	uProofData, err := fromStringSlices(reqIssue.UProof.ProofData)
	if err != nil {
		return err
	}
	UProof := qr.NewRepresentationProof(
		new(big.Int).SetBytes(reqIssue.UProof.ProofRandomData),
		new(big.Int).SetBytes(reqIssue.UProof.Challenge),
		uProofData,
	)

	commitmentsOfAttrsProofs := make([]*df.OpeningProof, len(reqIssue.CommitmentsOfAttrsProofs))
	for i, proof := range reqIssue.CommitmentsOfAttrsProofs {
		commitmentsOfAttrsProofs[i] = df.NewOpeningProof(
			new(big.Int).SetBytes(proof.ProofRandomData),
			new(big.Int).SetBytes(proof.Challenge),
			new(big.Int).SetBytes(proof.ProofData[0]),
			new(big.Int).SetBytes(proof.ProofData[1]),
		)
	}

	cReq := NewCredRequest(
		new(big.Int).SetBytes(reqIssue.Nym),
		fromByteSlices(reqIssue.KnownAttrs),
		fromByteSlices(reqIssue.CommitmentsOfAttrs),
		nymProof,
		new(big.Int).SetBytes(reqIssue.U),
		UProof,
		commitmentsOfAttrsProofs,
		new(big.Int).SetBytes(reqIssue.Nonce),
	)

	cred, AProof, err := org.IssueCred(cReq)
	if err != nil {
		return fmt.Errorf("error when issuing credential: %v", err)
	}

	resp = &pb.Response{
		Type: &pb.Response_IssuedCred{
			IssuedCred: &pb.IssuedCred{
				Cred: &pb.Cred{
					A:   cred.A.Bytes(),
					E:   cred.E.Bytes(),
					V11: cred.V11.Bytes(),
				},
				AProof: &pb.FiatShamirAlsoNeg{
					ProofRandomData: AProof.ProofRandomData.Bytes(),
					Challenge:       AProof.Challenge.Bytes(),
					ProofData:       []string{AProof.ProofData[0].String()},
				},
			},
		},
	}

	return stream.Send(resp)
}

func (s *Server) Update(ctx context.Context, req *pb.CredUpdateRequest) (*pb.IssuedCred, error) {
	org, err := LoadOrg("organization1", "../client/testdata/clSecKey.gob", "../client/testdata/clPubKey.gob")
	if err != nil {
		return nil, err
	}

	cred, AProof, err := org.UpdateCred(
		new(big.Int).SetBytes(req.Nym),
		new(big.Int).SetBytes(req.Nonce),
		fromByteSlices(req.NewKnownAttrs),
	)
	if err != nil {
		return nil, fmt.Errorf("error when updating credential: %v", err)
	}

	return &pb.IssuedCred{
		Cred: &pb.Cred{
			A:   cred.A.Bytes(),
			E:   cred.E.Bytes(),
			V11: cred.V11.Bytes(),
		},
		AProof: &pb.FiatShamirAlsoNeg{
			ProofRandomData: AProof.ProofRandomData.Bytes(),
			Challenge:       AProof.Challenge.Bytes(),
			ProofData:       []string{AProof.ProofData[0].String()},
		},
	}, nil
}

func (s *Server) Prove(stream pb.AnonCreds_ProveServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	org, err := LoadOrg("organization1", "../client/testdata/clSecKey.gob", "../client/testdata/clPubKey.gob")
	if err != nil {
		return err
	}

	nonce := org.GetProveCredNonce()
	resp := &pb.Response{
		Type: &pb.Response_Nonce{
			Nonce: &proto.BigInt{
				X1: nonce.Bytes(),
			},
		},
	}

	if err := stream.Send(resp); err != nil {
		return err
	}

	req, err = stream.Recv()
	if err != nil {
		return err
	}

	pReq := req.GetCredProve()

	knownAttrs := make([]*big.Int, len(pReq.KnownAttrs))
	for i, a := range pReq.KnownAttrs {
		knownAttrs[i] = new(big.Int).SetBytes(a)
	}

	commitmentsOfAttrs := make([]*big.Int, len(pReq.CommitmentsOfAttrs))
	for i, a := range pReq.CommitmentsOfAttrs {
		commitmentsOfAttrs[i] = new(big.Int).SetBytes(a)
	}

	pData, err := fromStringSlices(pReq.Proof.ProofData)
	if err != nil {
		return err
	}

	revealedKnownAttrsIndices := make([]int, len(pReq.RevealedKnownAttrs))
	for i, a := range pReq.RevealedKnownAttrs {
		revealedKnownAttrsIndices[i] = int(a)
	}

	revealedCommitmentsOfAttrsIndices := make([]int, len(pReq.RevealedCommitmentsOfAttrs))
	for i, a := range pReq.RevealedCommitmentsOfAttrs {
		revealedCommitmentsOfAttrsIndices[i] = int(a)
	}

	verified, err := org.ProveCred(
		new(big.Int).SetBytes(pReq.A),
		qr.NewRepresentationProof(
			new(big.Int).SetBytes(pReq.Proof.ProofRandomData),
			new(big.Int).SetBytes(pReq.Proof.Challenge),
			pData),
		revealedKnownAttrsIndices,
		revealedCommitmentsOfAttrsIndices,
		knownAttrs,
		commitmentsOfAttrs,
	)
	if err != nil {
		return err
	}

	resp = &pb.Response{
		Type: &pb.Response_Status{
			Status: &proto.Status{
				Success: verified,
			},
		},
	}

	return stream.Send(resp)
}
