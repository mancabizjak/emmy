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

	"github.com/emmyzkp/crypto/ec"
	"github.com/emmyzkp/emmy/anauth"
	"github.com/emmyzkp/emmy/anauth/ecpsys"
	"github.com/emmyzkp/emmy/anauth/psys"
	"github.com/stretchr/testify/assert"
)

func TestEndToEnd_ECPsys(t *testing.T) {
	tests := []struct {
		desc  string
		curve ec.Curve
	}{
		//{"P224", ec.P224}, // FIXME
		{"P256", ec.P256},
		//{"P384", ec.P384},  // FIXME
	}

	for _, tt := range tests {
		g := ec.NewGroup(tt.curve)
		caSk, caPk, err := psys.GenerateCAKeyPair()
		if err != nil {
			t.Errorf("error generating CA keypair: %v", err)
		}
		sk, pk := ecpsys.GenerateKeyPair(g)

		t.Run(tt.desc, func(t *testing.T) {
			testEndToEndECPsys(t, tt.curve, caSk, caPk, sk, pk)
		})
	}
}

func testEndToEndECPsys(t *testing.T, c ec.Curve, caSk *big.Int,
	caPk *psys.PubKey, sk *psys.SecKey, pk *ecpsys.PubKey) {
	ca := ecpsys.NewCAServer(caSk, caPk, c)
	org := ecpsys.NewOrgServer(c, sk, pk, caPk)
	// FIXME
	org.RegMgr = regKeyDB
	org.SessMgr, _ = anauth.NewRandSessionKeyGen(32)

	testSrv := newTestServer()
	testSrv.addService(ca)
	testSrv.addService(org)
	go testSrv.start()

	conn, err := getTestConn()
	if err != nil {
		t.Errorf("cannot establish connection to test server: %v", err)
	}

	caClient, err := ecpsys.NewCAClient(conn, c)
	if err != nil {
		t.Errorf("Error when initializing NewPseudonymsysCAClientEC")
	}

	// usually the endpoint is different from the one used for CA:
	c1, _ := ecpsys.NewClient(conn, c)
	userSecret := c1.GenerateMasterKey()

	masterNym := caClient.GenerateMasterNym(userSecret)
	caCert, err := caClient.GenerateCertificate(userSecret, masterNym)
	if err != nil {
		t.Errorf("Error when registering with CA: %s", err.Error())
	}

	//nym generation should fail with invalid registration key
	_, err = c1.GenerateNym(userSecret, caCert, "029uywfh9udni")
	assert.NotNil(t, err, "Should produce an error")

	nym1, err := c1.GenerateNym(userSecret, caCert, "testRegKey3")
	if err != nil {
		t.Errorf(err.Error())
	}

	//nym generation should fail the second time with the same registration key
	_, err = c1.GenerateNym(userSecret, caCert, "testRegKey3")
	assert.NotNil(t, err, "Should produce an error")

	orgName := "org1" // FIXME remove

	cred, err := c1.ObtainCredential(userSecret, nym1, pk)
	if err != nil {
		t.Errorf(err.Error())
	}

	// register with org2
	// create a client to communicate with org2
	caClient1, _ := ecpsys.NewCAClient(conn, c)
	caCert1, err := caClient1.GenerateCertificate(userSecret, masterNym)
	if err != nil {
		t.Errorf("Error when registering with CA")
	}

	// c2 connects to the same server as c1, so what we're really testing here is
	// using transferCredential to authenticate with the same organization and not
	// transferring credentials to another organization
	c2, _ := ecpsys.NewClient(conn, c)
	nym2, err := c2.GenerateNym(userSecret, caCert1, "testRegKey4")
	if err != nil {
		t.Errorf(err.Error())
	}

	// Authentication should succeed
	sessKey1, err := c2.TransferCredential(orgName, userSecret, nym2, cred)
	assert.NotNil(t, sessKey1, "Should authenticate and obtain a valid (non-nil) session key")
	assert.Nil(t, err, "Should not produce an error")

	// Authentication should fail because the user doesn't have the right secret
	wrongUserSecret := big.NewInt(3952123123)
	sessKey, err := c2.TransferCredential(orgName, wrongUserSecret, nym2, cred)
	assert.Nil(t, sessKey, "Authentication should fail, and session key should be nil")
	assert.NotNil(t, err, "Should produce an error")

	conn.Close()
	testSrv.teardown()
}
