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
	"bytes"
	"encoding/gob"

	"github.com/xlab-si/emmy/crypto/groups"
	"github.com/xlab-si/emmy/storage"
)

/*type ConfigHandler interface {
	//gob.GobEncoder
	Store() error
	Read() error
}*/

type PseudonymSystemConfig struct {
	SchnorrGroup *groups.SchnorrGroup
}

func GeneratePseudonymSystemConfig() *PseudonymSystemConfig {
	group, _ := groups.NewSchnorrGroup(256)
	//orgSecKey, orgPubKey := pseudonymsys.GenerateKeyPair(group)

	return &PseudonymSystemConfig{
		//filename:     "pseudonym_system",
		SchnorrGroup: group,
	}
}

func ReadConfig(path string, config interface{}) error {
	data, err := storage.Load(path)
	if err != nil {
		return err
	}

	buf := bytes.Buffer{}
	buf.Write(data)
	dec := gob.NewDecoder(&buf)

	return dec.Decode(config)
}

func StoreConfig(path string, config interface{}) error {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(config); err != nil {
		return err
	}

	return storage.Store(buf.Bytes(), path)
}
