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
	"fmt"
	"os"
	"testing"

	"github.com/pkg/errors"
	. "gopkg.in/check.v1"
)

func TestServer(t *testing.T) { TestingT(t) }

type ServerSuite struct {
	emmyDir string
}

var _ = Suite(&ServerSuite{})

func (s *ServerSuite) SetUpSuite(c *C) {
	s.emmyDir = fmt.Sprintf("%s/%s", c.MkDir(), emmyDirName)
}

func (s *ServerSuite) TestBootstrap(c *C) {
	err := Bootstrap(s.emmyDir)
	c.Assert(err, IsNil)
	removeTestDir(s.emmyDir)
}

// "re-bootstrapping emmy server with existing configuration",
func (s *ServerSuite) TestBootstrapInvalid(c *C) {
	createTestDir(s.emmyDir)
	err := Bootstrap(s.emmyDir)

	c.Assert(err, NotNil)
	c.Check(err, ErrorMatches, "emmy directory .*/.emmy already exists")

	removeTestDir(s.emmyDir)
}

// "clean non-emmy directory
func (s *ServerSuite) TestCleanForeignDir(c *C) {
	err := Clean(c.MkDir(), false)
	c.Assert(err, NotNil)
	c.Check(err, ErrorMatches, "skipping .*")

}

func (s *ServerSuite) TestCleanNonexistingEmmyDir(c *C) {
	err := Clean(s.emmyDir, false)
	c.Assert(err, IsNil)
}

func (s *ServerSuite) TestClean(c *C) {
	createTestDir(s.emmyDir)
	err := Clean(s.emmyDir, false)
	c.Assert(err, IsNil)
	removeTestDir(s.emmyDir)
}

func removeTestDir(dir string) {
	if err := os.RemoveAll(dir); err != nil {
		err = errors.Wrap(err, "failed to remove test directory")
		panic(err)
	}
}

func createTestDir(dir string) {
	if err := os.Mkdir(dir, 0744); err != nil {
		err = errors.Wrap(err, "failed to create test directory")
		panic(err)
	}
}
