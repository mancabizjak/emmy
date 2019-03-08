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

	"github.com/stretchr/testify/require"

	"github.com/spf13/viper"

	"github.com/stretchr/testify/assert"

	"github.com/emmyzkp/emmy/anauth"

	"google.golang.org/grpc"

	"github.com/emmyzkp/emmy/anauth/cl"
	pb "github.com/emmyzkp/emmy/anauth/cl/clpb"
)

func TestEndToEnd_CL(t *testing.T) {
	tests := []struct {
		desc            string
		params          *pb.Params
		acceptableCreds map[string][]string
		attributes      map[string]interface{}
	}{
		{"Defaults",
			cl.GetDefaultParamSizes(),
			map[string][]string{
				"org1": {"name", "age"},
				"org2": {"gender"},
			},
			map[string]interface{}{
				"name":      map[string]interface{}{"type": "string"},
				"gender":    map[string]interface{}{"type": "string"},
				"graduated": map[string]interface{}{"type": "string"},
				"age": map[string]interface{}{
					"type":  "int64",
					"known": "false",
				},
			},
		},
	}

	for _, tt := range tests {
		keys, err := cl.GenerateKeyPair(tt.params, cl.NewAttrCount(3, 1, 0))
		if err != nil {
			t.Errorf("error creating keypair: %v", err)
		}

		v := viper.New()
		v.Set("acceptable_creds", tt.acceptableCreds)
		v.Set("attributes", tt.attributes)

		clSrv, err := cl.NewServer(recDB, keys, v)
		if err != nil {
			t.Errorf("error creating cl server: %v", err)
		}

		// FIXME
		clSrv.RegMgr = regKeyDB
		clSrv.SessMgr, _ = anauth.NewRandSessionKeyGen(32)

		testSrv := newTestSrv()
		testSrv.addService(clSrv)
		go testSrv.start()

		conn, err := getTestConn()
		if err != nil {
			t.Errorf("cannot establish connection to test server: %v", err)
		}

		t.Run(tt.desc, func(t *testing.T) {
			testEndToEndCL(t, conn)
		})

		conn.Close()
		testSrv.teardown()
	}
}

// TestCL requires a running server.
func testEndToEndCL(t *testing.T, conn *grpc.ClientConn) {
	client := cl.NewClient(conn)

	params, pubKey, err := client.GetPublicParams()
	require.NoError(t, err)

	cs, err := client.GetCredStructure()
	require.NoError(t, err)

	name, _ := cs.GetAttr("name")
	err = name.UpdateValue("Jack")
	assert.NoError(t, err)
	gender, _ := cs.GetAttr("gender")
	err = gender.UpdateValue("M")
	assert.NoError(t, err)
	graduated, _ := cs.GetAttr("graduated")
	err = graduated.UpdateValue("true")
	assert.NoError(t, err)
	age, _ := cs.GetAttr("age")
	err = age.UpdateValue(50)
	assert.NoError(t, err)

	acceptableCreds, err := client.GetAcceptableCreds()
	if err != nil {
		t.Errorf("error when retrieving acceptable creds: %v", err)
	}
	revealedAttrs := acceptableCreds["org1"] // FIXME

	masterSecret := pubKey.GenerateUserMasterSecret()
	cm, err := cl.NewCredManager(params, pubKey, masterSecret, cs)
	if err != nil {
		t.Errorf("error when creating a user: %v", err)
	}

	regKey := "key1"
	regKeyDB.Insert(regKey)
	cred, err := client.IssueCredential(cm, regKey)
	if err != nil {
		t.Errorf("error when calling IssueCred: %v", err)
	}

	// create new CredManager (updating or proving usually does not happen at the same time
	// as issuing)
	cm, err = cl.NewCredManagerFromExisting(cm.Nym, cm.V1,
		cm.CredReqNonce, params, pubKey, masterSecret, cs, cm.CommitmentsOfAttrs)
	if err != nil {
		t.Errorf("error when calling NewCredManagerFromExisting: %v", err)
	}

	sessKey, err := client.ProveCredential(cm, cred, revealedAttrs)
	if err != nil {
		t.Errorf("error when proving possession of a credential: %v", err)
	}
	assert.NotNil(t, sessKey, "possesion of a credential proof failed")

	// modify some attributes and get updated credential
	name, err = cs.GetAttr("name")
	err = name.UpdateValue("Jim")
	assert.NoError(t, err)

	cred1, err := client.UpdateCredential(cm, cs)
	if err != nil {
		t.Errorf("error when updating credential: %v", err)
	}

	sessKey, err = client.ProveCredential(cm, cred1, []string{"name", "dog"})
	if err != nil {
		t.Errorf("error when proving possession of an updated credential: %v", err)
	}

	assert.NotNil(t, sessKey,
		"possesion of an updated credential proof failed")
}

func intsToBig(s ...int) []*big.Int {
	bigS := make([]*big.Int, len(s))
	for i, el := range s {
		bigS[i] = big.NewInt(int64(el))
	}
	return bigS
}
