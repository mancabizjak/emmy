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

package emmy

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// Minimal allowed length of the session key, in bytes
// This is to prevent possible mistakes security reasons.
const MIN_SESSION_KEY_BYTE_LEN = 24

type SessionHandler interface {
	GenerateSessionKey() (*string, error)
}

type SessionManager struct {
	sessionKeyByteLen int
}

func NewSessionManager(n int) (*SessionManager, error) {
	var err error
	if n < MIN_SESSION_KEY_BYTE_LEN {
		err = fmt.Errorf("desired length of the session key (%d B) is too short, falling back to %d B",
			n, MIN_SESSION_KEY_BYTE_LEN)
		n = MIN_SESSION_KEY_BYTE_LEN
	}
	return &SessionManager{
		sessionKeyByteLen: n,
	}, err
}

// generateSessionKey produces a secure random n-byte session key and returns its
// base64-encoded representation that is URL-safe.
// It reports an error if n is less than MIN_SESSION_KEY_BYTE_LEN.
func (m *SessionManager) GenerateSessionKey() (*string, error) {
	randBytes := make([]byte, m.sessionKeyByteLen)

	// reads m.sessionKeyByteLen random bytes (e.g. len(randBytes)) to randBytes array
	_, err := rand.Read(randBytes)

	// an error may occur if the system's secure RNG doesn't function properly, in which case
	// we can't generate a secure session key
	if err != nil {
		return nil, err
	}

	sessionKey := base64.URLEncoding.EncodeToString(randBytes)
	return &sessionKey, nil
}
