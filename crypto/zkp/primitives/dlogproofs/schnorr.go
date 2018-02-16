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

package dlogproofs

import (
	"math/big"

	"fmt"

	"github.com/xlab-si/emmy/crypto/commitments"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
)

// Proving that it knows secret such that g^secret = h (mod p).
type SchnorrProver struct {
	Group  *groups.SchnorrGroup
	secret *big.Int // secret
	a      *big.Int
	r      *big.Int // random data
	//pedersenCommitter *commitments.PedersenCommitter // only needed for ZKP mode
	//mode              zkp.Mode
}

func NewSchnorrProver(group *groups.SchnorrGroup) *SchnorrProver {
	return &SchnorrProver{
		Group: group,
	}
}

func (p *SchnorrProver) setParams(secret, a, r *big.Int) {
	p.a = a
	p.secret = secret
	p.r = r
}

// GenerateCommitment sets prover's secret and a, and returns x =  a^r % p, where r is random
func (p *SchnorrProver) GenerateRandomData(secret, a *big.Int) *big.Int {
	r := common.GetRandomInt(p.Group.Q)
	p.setParams(secret, a, r)

	x := p.Group.Exp(a, r)
	return x
}

// GenerateProofData receives challenge c (as defined by the verifier) and
// returns z = r + c*secret
func (p *SchnorrProver) GenerateProofData(c *big.Int) *big.Int {
	z := new(big.Int)
	z.Mul(c, p.secret)
	z.Add(z, p.r)
	z.Mod(z, p.Group.Q)

	return z
}

type SchnorrZKPProver struct {
	*SchnorrProver
	pedersenCommitter *commitments.PedersenCommitter
}

func NewSchnorrZKPProver(group *groups.SchnorrGroup) *SchnorrZKPProver {
	return &SchnorrZKPProver{
		SchnorrProver:     NewSchnorrProver(group),
		pedersenCommitter: commitments.NewPedersenCommitter(group),
	}
}

func (p *SchnorrZKPProver) GenerateCommitment(secret, a, h *big.Int) *big.Int {
	p.pedersenCommitter.SetH(h)
	r := p.SchnorrProver.GenerateRandomData(secret, a)
	commitment, err := p.pedersenCommitter.GetCommitMsg(r) // TODO check secodnd param
	if err != nil {
		fmt.Println("error in kmrtrtm", err)
	}
	p.r = r

	return commitment
}

type SchnorrVerifier struct {
	Group     *groups.SchnorrGroup
	x         *big.Int
	a         *big.Int
	b         *big.Int
	challenge *big.Int
	//PedersenReceiver *commitments.PedersenReceiver // only needed for ZKP mode
	//mode             zkp.Mode
}

func NewSchnorrVerifier(group *groups.SchnorrGroup) *SchnorrVerifier {
	return &SchnorrVerifier{
		Group: group,
	}
}

func (v *SchnorrVerifier) SetParams(x, a, b *big.Int) {
	v.x = x
	v.a = a
	v.b = b
}

// GenerateChallenge is used in ZKP where challenge needs to be
// chosen (and committed to) before sigma protocol starts.
func (v *SchnorrVerifier) GenerateChallenge() *big.Int {
	c := common.GetRandomInt(v.Group.Q)
	v.challenge = c
	return c
}

// It receives z = r + c*secret. It returns true if a^z = a^r * (a^secret) ^ challenge,
// otherwise false.
func (v *SchnorrVerifier) Verify(z *big.Int) bool {
	left := v.Group.Exp(v.a, z)
	r1 := v.Group.Exp(v.b, v.challenge)
	fmt.Println("r1", r1)
	fmt.Println("v.x", v.x)
	right := v.Group.Mul(r1, v.x)

	return left.Cmp(right) == 0
}

type SchnorrZKPVerifier struct {
	*SchnorrVerifier
	pedersenReceiver *commitments.PedersenReceiver
}

func NewSchnorrZKPVerifier(group *groups.SchnorrGroup) *SchnorrZKPVerifier {
	return &SchnorrZKPVerifier{
		SchnorrVerifier:  NewSchnorrVerifier(group),
		pedersenReceiver: commitments.NewPedersenReceiver(group),
	}
}

func (v *SchnorrZKPVerifier) Verify(z, randData, r *big.Int) bool {
	proofOk := v.SchnorrVerifier.Verify(z)
	decomitmentOk := v.pedersenReceiver.CheckDecommitment(randData, r)
	return proofOk && decomitmentOk
}

func (v *SchnorrZKPVerifier) GetH() *big.Int {
	return v.pedersenReceiver.GetH()
}

func (v *SchnorrZKPVerifier) GetChallenge() *big.Int {
	return v.pedersenReceiver.GetH()
}
