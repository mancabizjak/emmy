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
	removeTestDir(c, s.emmyDir)
}

// "re-bootstrapping emmy server with existing configuration",
func (s *ServerSuite) TestBootstrapInvalid(c *C) {
	defer handleTestDir(c, s.emmyDir)()
	err := Bootstrap(s.emmyDir)
	c.Assert(err, NotNil)
	c.Check(err, ErrorMatches, "emmy directory .*/.emmy already exists")
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
	defer handleTestDir(c, s.emmyDir)
	err := Clean(s.emmyDir, false)
	c.Assert(err, IsNil)
}

// HELPERS

// handleTestDir is a convenience helper.
// It returns a closure of the function that removes the given directory.
// This way, the caller that needs to create test directory and remove it afterwards can
// simply call 'defer handleTestDir(t, dir)' and if either creation or deletion of directory fails,
// the test itself will fail.
// This is convenient, because it does not pollute the actual test code with error handling.
func handleTestDir(c *C, dir string) func() {
	if err := os.Mkdir(dir, 0744); err != nil {
		err = errors.Wrap(err, "failed to create test directory")
		c.Fatal(err)
	}

	return func() { removeTestDir(c, dir) }
}

// removeTestDir removes a given directory, failing the test in case of error.
func removeTestDir(c *C, dir string) {
	if err := os.RemoveAll(dir); err != nil {
		err = errors.Wrap(err, "failed to remove test directory")
		c.Fatal(err)
	}
}
