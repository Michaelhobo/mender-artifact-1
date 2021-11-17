// Copyright 2021 Northern.tech AS
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

package cli

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/mendersoftware/mender-artifact/artifact"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

const (
	PublicValidateRSAKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDSTLzZ9hQq3yBB+dMDVbKem6ia
v1J6opg6DICKkQ4M/yhlw32BCGm2ArM3VwQRgq6Q1sNSq953n5c1EO3Xcy/qTAKc
XwaUNml5EhW79AdibBXZiZt8fMhCjUd/4ce3rLNjnbIn1o9L6pzV4CcVJ8+iNhne
5vbA+63vRCnrc8QuYwIDAQAB
-----END PUBLIC KEY-----`
	PublicValidateRSAKeyError = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDSTLzZ9hQq3yBB+dMDVbKem6ia
v1J6opg6DICKkQ4M/yhlw32BCGm2ArM3VwQRgq6Q1sNSq953n5c1EO3Xcy/qTAKc
XwaUNml5EhW79AdibBXZiZt8fMhCjUd/4ce3rLNjnbIn1o9L6pzV4CcVJ8+iNhne
5vbA+63vRCnrc8QuYwIDAQAC
-----END PUBLIC KEY-----`
	PublicValidateRSAKeyInvalid = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDSTLzZ9hQq3yBB+dMDVbKem6ia
v1J6opg6DICKkQ4M/yhlw32BCGm2ArM3VwQRgq6Q1sNSq953n5c1EO3Xcy/qTAKc
5vbA+63vRCnrc8QuYwIDA
-----END PUBLIC KEY-----`
	PrivateValidateRSAKey = `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDSTLzZ9hQq3yBB+dMDVbKem6iav1J6opg6DICKkQ4M/yhlw32B
CGm2ArM3VwQRgq6Q1sNSq953n5c1EO3Xcy/qTAKcXwaUNml5EhW79AdibBXZiZt8
fMhCjUd/4ce3rLNjnbIn1o9L6pzV4CcVJ8+iNhne5vbA+63vRCnrc8QuYwIDAQAB
AoGAQKIRELQOsrZsxZowfj/ia9jPUvAmO0apnn2lK/E07k2lbtFMS1H4m1XtGr8F
oxQU7rLyyP/FmeJUqJyRXLwsJzma13OpxkQtZmRpL9jEwevnunHYJfceVapQOJ7/
6Oz0pPWEq39GCn+tTMtgSmkEaSH8Ki9t32g9KuQIKBB2hbECQQDsg7D5fHQB1BXG
HJm9JmYYX0Yk6Z2SWBr4mLO0C4hHBnV5qPCLyevInmaCV2cOjDZ5Sz6iF5RK5mw7
qzvFa8ePAkEA46Anom3cNXO5pjfDmn2CoqUvMeyrJUFL5aU6W1S6iFprZ/YwdHcC
kS5yTngwVOmcnT65Vnycygn+tZan2A0h7QJBAJNlowZovDdjgEpeCqXp51irD6Dz
gsLwa6agK+Y6Ba0V5mJyma7UoT//D62NYOmdElnXPepwvXdMUQmCtpZbjBsCQD5H
VHDJlCV/yzyiJz9+tZ5giaAkO9NOoUBsy6GvdfXWn2prXmiPI0GrrpSvp7Gj1Tjk
r3rtT0ysHWd7l+Kx/SUCQGlitd5RDfdHl+gKrCwhNnRG7FzRLv5YOQV81+kh7SkU
73TXPIqLESVrqWKDfLwfsfEpV248MSRou+y0O1mtFpo=
-----END RSA PRIVATE KEY-----`
)

var validateTests = []struct {
	version       int
	writeKey      []byte
	validateKey   []byte
	expectedError string
}{
	{2, nil, nil, ""},
	{2, []byte(PrivateValidateRSAKey), []byte(PublicValidateRSAKey), ""},
	{2, []byte(PrivateValidateRSAKey), []byte(PublicValidateRSAKeyError),
		"verification error"},
	{2, []byte(PrivateValidateRSAKey), []byte(PublicValidateRSAKeyInvalid),
		"failed to parse public key"},
	{2, []byte(PrivateValidateRSAKey), nil, "missing key"},      // MEN-2802
	{2, nil, []byte(PublicValidateRSAKey), "missing signature"}, // MEN-2155
}

func TestValidate(t *testing.T) {
	for i, test := range validateTests {
		fmt.Printf("---- Running test validate-%d ----\n", i)
		art, err := WriteTestArtifact(test.version, "", test.writeKey)
		assert.NoError(t, err)
		validater, err := artifact.NewPKIVerifier(test.validateKey)
		assert.NoError(t, err)
		err = validate(art, validater)
		if test.expectedError == "" {
			assert.NoError(t, err)
		} else {
			assert.Error(t, err)
			assert.Contains(t, err.Error(), test.expectedError)
		}
		fmt.Println("---------------------------------")
	}
}

func TestArtifactsValidate(t *testing.T) {
	// first create archive, that we will be able to read
	updateTestDir, _ := ioutil.TempDir("", "update")
	defer os.RemoveAll(updateTestDir)

	err := WriteArtifact(updateTestDir, 2, "")
	assert.NoError(t, err)

	err = Run([]string{"mender-artifact", "validate",
		filepath.Join(updateTestDir, "artifact.mender")})
	assert.NoError(t, err)
}

func TestArtifactsValidateError(t *testing.T) {
	err := Run([]string{"mender-artifact", "validate"})
	assert.Error(t, err)
	assert.Contains(t, errors.Cause(err).Error(),
		"Nothing specified, nothing validated.")

	fakeErrWriter.Reset()
	err = Run([]string{"mender-artifact", "validate", "non-existing"})
	assert.Error(t, err)
	assert.Equal(t, errArtifactOpen, lastExitCode)
	assert.Contains(t, fakeErrWriter.String(), "no such file")
}
