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

package test

import (
	"math/big"
	"testing"

	"github.com/emmyzkp/emmy/anauth/cl"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

func intsToBig(s ...int) []*big.Int {
	bigS := make([]*big.Int, len(s))
	for i, el := range s {
		bigS[i] = big.NewInt(int64(el))
	}
	return bigS
}

func TestEndToEnd_CL(t *testing.T) {
	tests := []struct {
		desc   string
		params *cl.Params
		attrs  *cl.Attrs
	}{
		{"Defaults",
			cl.GetDefaultParamSizes(),
			cl.NewAttrs(
				intsToBig(7, 6, 5, 22),
				intsToBig(11, 13, 19),
				intsToBig(9, 17)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			testEndToEndCL(t, tt.params, tt.attrs)
		})
	}
}

// TestCL requires a running server.
func testEndToEndCL(t *testing.T, params *cl.Params, attrs *cl.Attrs) {
	keys, err := cl.GenerateKeyPair(params)
	if err != nil {
		t.Errorf("error creating keypair: %v", err)
	}

	clSrv, err := cl.NewServer(recDB, keys)
	if err != nil {
		t.Errorf("error creating cl server: %v", err)
	}

	testSrv.addService(clSrv)
	go testSrv.start()

	masterSecret := keys.Pub.GenerateUserMasterSecret()

	credManager, err := cl.NewCredManager(params, keys.Pub, masterSecret, attrs)
	if err != nil {
		t.Errorf("error when creating a user: %v", err)
	}

	grpc.EnableTracing = false
	conn, err := grpc.Dial(testAddr,
		grpc.WithInsecure(),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Errorf("cannot establish connection to test server: %v", err)
	}
	client, err := cl.NewClient(conn)
	if err != nil {
		t.Errorf("Error when initializing NewClient")
	}

	cred, err := client.IssueCredential(credManager)
	if err != nil {
		t.Errorf("error when calling IssueCred: %v", err)
	}

	// create new CredManager (updating or proving usually does not happen at the same time
	// as issuing)
	credManager, err = cl.NewCredManagerFromExisting(credManager.Nym, credManager.V1,
		credManager.CredReqNonce, params, keys.Pub, masterSecret, attrs,
		credManager.CommitmentsOfAttrs)
	if err != nil {
		t.Errorf("error when calling NewCredManagerFromExisting: %v", err)
	}

	revealedKnownAttrsIndices := []int{1, 2}      // reveal only the second and third known attribute
	revealedCommitmentsOfAttrsIndices := []int{0} // reveal only the commitment of the first attribute (of those of which only commitments are known)

	proved, err := client.ProveCredential(credManager, cred, attrs.Known,
		revealedKnownAttrsIndices,
		revealedCommitmentsOfAttrsIndices)
	if err != nil {
		t.Errorf("error when proving possession of a credential: %v", err)
	}
	assert.True(t, proved, "possesion of a credential proof failed")

	newKnownAttrs := []*big.Int{big.NewInt(17), big.NewInt(18), big.NewInt(19), big.NewInt(27)}
	cred1, err := client.UpdateCredential(credManager, newKnownAttrs)
	if err != nil {
		t.Errorf("error when updating credential: %v", err)
	}

	proved1, err := client.ProveCredential(credManager, cred1, newKnownAttrs, revealedKnownAttrsIndices,
		revealedCommitmentsOfAttrsIndices)
	if err != nil {
		t.Errorf("error when proving possession of an updated credential: %v", err)
	}

	assert.True(t, proved1, "possesion of an updated credential proof failed")

	testSrv.teardown()
}
