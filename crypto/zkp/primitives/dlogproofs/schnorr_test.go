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
	"testing"

	"fmt"

	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
)

var group *groups.SchnorrGroup
var groupOrder, secret, a, b *big.Int

func TestMain(m *testing.M) {
	group, _ = groups.NewSchnorrGroup(256)
	groupOrder = new(big.Int).Sub(group.P, big.NewInt(1))
	secret = common.GetRandomInt(group.Q)
	a, _ = common.GetGeneratorOfZnSubgroup(group.P, groupOrder, group.Q)
	b = group.Exp(a, secret)

	m.Run()
}

func TestSchnorrSigma(t *testing.T) {
	prover := NewSchnorrProver(group)
	verifier := NewSchnorrVerifier(group)

	x := prover.GenerateRandomData(secret, a)
	verifier.SetParams(x, a, b)
	c := verifier.GenerateChallenge()
	z := prover.GenerateProofData(c)
	proved := verifier.Verify(z)

	assert.Equal(t, proved, true, "schnorr sigma proof does not work")
}

func TestSchnorrZKP(t *testing.T) {
	prover := NewSchnorrZKPProver(group)
	verifier := NewSchnorrZKPVerifier(group)

	h := verifier.GetH()
	commitment := prover.GenerateCommitment(secret, a, h)
	fmt.Println("commitment", commitment)
	verifier.SetParams(commitment, a, b)
	c := verifier.GenerateChallenge()
	z := prover.GenerateProofData(c)
	randData, r := prover.pedersenCommitter.GetDecommitMsg()
	proved := verifier.Verify(z, randData, r)

	assert.Equal(t, proved, true, "schnorr ZKP does not work")
}
