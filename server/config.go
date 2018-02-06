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

package server

import (
	"math/big"

	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/crypto/groups"
	"github.com/xlab-si/emmy/crypto/zkp/schemes/pseudonymsys"
)

type cryptoConfig struct {
	group    *groups.SchnorrGroup
	secKey   *pseudonymsys.Key
	secKeyEC *pseudonymsys.Key
	pubKey   *pseudonymsys.Key
	pubKeyEC *pseudonymsys.PubKeyEC
	caSecKey *big.Int
	caPubKey *pseudonymsys.Key
	qrRSA    *groups.QRRSA
}

func newCryptoConfig(orgName string) (*cryptoConfig, error) {
	group, err := config.LoadSchnorrGroup()
	if err != nil {
		return nil, err
	}

	secKey, err := config.LoadPseudonymsysOrgSecrets(orgName)
	if err != nil {
		return nil, err
	}

	secKeyEC, err := config.LoadPseudonymsysOrgSecretsEC(orgName)
	if err != nil {
		return nil, err
	}

	pubKey, err := config.LoadPseudonymsysOrgPubKeys(orgName)
	if err != nil {
		return nil, err
	}

	pubKeyEC, err := config.LoadPseudonymsysOrgPubKeysEC(orgName)
	if err != nil {
		return nil, err
	}

	caSecKey, err := config.LoadPseudonymsysCASecret()
	if err != nil {
		return nil, err
	}

	caPubKey, err := config.LoadPseudonymsysCAPubKey()
	if err != nil {
		return nil, err
	}

	qrRSA, err := config.LoadQRRSA()
	if err != nil {
		return nil, err
	}

	return &cryptoConfig{
		group:    group,
		secKey:   secKey,
		secKeyEC: secKeyEC,
		pubKey:   pubKey,
		pubKeyEC: pubKeyEC,
		caSecKey: caSecKey,
		caPubKey: caPubKey,
		qrRSA:    qrRSA,
	}, nil
}
