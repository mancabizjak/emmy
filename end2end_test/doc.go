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

// Package end2end_test contains integration tests that involve emmy
// clients and emmy server.
//
// All the tests defined in this package handle some aspect of
// client-server communication. The nature of these tests is such that
// we run the client and check whether response from the server is what
// we expect.
//
// The reasons for putting these tests into a dedicated package are:
// 1) they are not simple unit tests,
// 2) because they are not unit tests, they do not fit nicely into any of
// the other packages (neither client nor server packages are particularly
// appropriate, since both client and server need to be involved).
package end2end_test
