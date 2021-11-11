package artifact

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"hash/crc32"
	"testing"
	"time"

	gax "github.com/googleapis/gax-go/v2"
	"github.com/pkg/errors"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	rsaKeyName           = "test/key/rsa"
	ecdsaKeyName         = "test/key/ecdsa"
	pubKeyPEMHeader      = "PUBLIC KEY"
	ecdsaPubKeyPEMHeader = ""
)

var (
	availableKMSKeys = map[string]testSigningKey{ // key name -> keypair
		rsaKeyName: {
			private: PrivateRSAKey,
			public:  PublicRSAKey,
		},
		ecdsaKeyName: {
			private: PrivateECDSAKey,
			public:  PublicECDSAKey,
		},
	}
)

func TestGoogleKMSSignAndVerify(t *testing.T) {
	tests := map[string]*signAndVerifyTestCase{
		"rsa": {
			keyName: rsaKeyName,
		},
		"ecdsa": {
			keyName: ecdsaKeyName,
		},
		"wrong key name": {
			keyName:     "invalid key name",
			wantSignErr: true,
		},
		"corrupted signature rsa": {
			signClient:  &fakeGoogleKMSClient{corruptSigningCRC: true},
			keyName:     rsaKeyName,
			wantSignErr: true,
		},
		"corrupted signature ecdsa": {
			signClient:  &fakeGoogleKMSClient{corruptSigningCRC: true},
			keyName:     ecdsaKeyName,
			wantSignErr: true,
		},
		"corrupted public key during signing rsa": {
			signClient:  &fakeGoogleKMSClient{corruptPublicKeyCRC: true},
			keyName:     rsaKeyName,
			wantSignErr: true,
		},
		"corrupted public key during signing ecdsa": {
			signClient:  &fakeGoogleKMSClient{corruptPublicKeyCRC: true},
			keyName:     ecdsaKeyName,
			wantSignErr: true,
		},
		"corrupted public key during verification rsa": {
			verifyClient:  &fakeGoogleKMSClient{corruptPublicKeyCRC: true},
			keyName:       rsaKeyName,
			wantVerifyErr: true,
		},
		"corrupted public key during verification ecdsa": {
			verifyClient:  &fakeGoogleKMSClient{corruptPublicKeyCRC: true},
			keyName:       ecdsaKeyName,
			wantVerifyErr: true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			msg := []byte("some msg")

			// If either client is nil, set it to a default one.
			if test.signClient == nil {
				test.signClient = &fakeGoogleKMSClient{}
			}
			if test.verifyClient == nil {
				test.verifyClient = &fakeGoogleKMSClient{}
			}
			kmsSigner := &GoogleKMS{
				name:       test.keyName,
				client:     test.signClient,
				rpcTimeout: 60 * time.Second,
			}
			kmsVerifier := &GoogleKMS{
				name:       test.keyName,
				client:     test.verifyClient,
				rpcTimeout: 60 * time.Second,
			}

			// Start by signing.
			sig, err := kmsSigner.Sign(msg)
			if err == nil && test.wantSignErr {
				t.Errorf("Sign: got nil error, want an error")
				return
			}
			if err != nil && !test.wantSignErr {
				t.Errorf("Sign: %v", err)
				return
			}

			// If we expected an error during signing, skip the verification.
			if test.wantSignErr {
				return
			}

			// Make sure verification works with the given signature.
			err = kmsVerifier.Verify(msg, sig)
			if err == nil && test.wantVerifyErr {
				t.Errorf("Verify: got nil error, want an error")
				return
			}
			if err != nil && !test.wantVerifyErr {
				t.Errorf("Verify: %v", err)
			}
		})
	}
}

func TestGoogleKMSSignatureCompatibility(t *testing.T) {
	tests := []string{rsaKeyName, ecdsaKeyName}
	for _, keyName := range tests {
		t.Run(keyName, func(t *testing.T) {
			msg := []byte("some msg")
			kmsSigner := &GoogleKMS{
				name:       keyName,
				client:     &fakeGoogleKMSClient{},
				rpcTimeout: 60 * time.Second,
			}
			goldenSigner := NewSigner([]byte(availableKMSKeys[keyName].private))
			goldenVerifier := NewVerifier([]byte(availableKMSKeys[keyName].public))

			// Sign with Google KMS, verify with golden verifier.
			sig, err := kmsSigner.Sign(msg)
			if err != nil {
				t.Errorf("Sign: %v", err)
				return
			}
			if err := goldenVerifier.Verify(msg, sig); err != nil {
				t.Errorf("Golden Verify: %v", err)
				return
			}

			// Sign with golden signer, verify with Google KMS.
			goldenSig, err := goldenSigner.Sign(msg)
			if err != nil {
				t.Errorf("Golden Sign: %v", err)
				return
			}
			if err := kmsSigner.Verify(msg, goldenSig); err != nil {
				t.Errorf("Verify: %v", err)
			}
		})
	}
}

type signAndVerifyTestCase struct {
	// Optionally specify a client for signing.
	// If nil, a default client will be used.
	signClient *fakeGoogleKMSClient
	// Optionally specify a client for verification.
	// If nil, a default client will be used.
	verifyClient  *fakeGoogleKMSClient
	keyName       string
	wantSignErr   bool
	wantVerifyErr bool
}

type fakeGoogleKMSClient struct {
	corruptSigningCRC   bool
	corruptPublicKeyCRC bool
}

func (f *fakeGoogleKMSClient) AsymmetricSign(_ context.Context, req *kmspb.AsymmetricSignRequest, _ ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	key, err := f.findKey(req.Name)
	if err != nil {
		return nil, err
	}
	sm, err := getKeyAndSignMethod([]byte(key.private))
	if err != nil {
		return nil, fmt.Errorf("key %q: %v", req.Name, err)
	}

	crcTable := crc32.MakeTable(crc32.Castagnoli)
	digestCRC32C := crc32.Checksum(req.Digest.GetSha256(), crcTable)
	verifiedDigestCRC32C := int64(digestCRC32C) == req.DigestCrc32C.Value

	dec := make([]byte, base64.StdEncoding.DecodedLen(len(req.Digest.GetSha256())))
	decLen, err := base64.StdEncoding.Decode(dec, req.Digest.GetSha256())
	if err != nil {
		return nil, fmt.Errorf("key %q: %v", req.Name, err)
	}

	// We can't reuse sm.method.sign because those functions will hash the data
	// an additional time. We just want the signature, since we only have the
	// hash available in this function.
	var sig []byte
	switch sm.method.(type) {
	case *RSA:
		sig, err = rsa.SignPKCS1v15(rand.Reader, sm.key.(*rsa.PrivateKey), crypto.SHA256, dec[:decLen])
		if err != nil {
			return nil, fmt.Errorf("key %q: %v", req.Name, err)
		}
	case *ECDSA256:
		sig, err = ecdsa.SignASN1(rand.Reader, sm.key.(*ecdsa.PrivateKey), dec[:decLen])
		if err != nil {
			return nil, fmt.Errorf("key %q: %v", req.Name, err)
		}
	default:
		return nil, fmt.Errorf("key %q: unsupported signing algorithm", req.Name)
	}

	sigBase64 := make([]byte, base64.StdEncoding.EncodedLen(len(sig)))
	base64.StdEncoding.Encode(sigBase64, sig)

	sigCRC32C := crc32.Checksum(sigBase64, crcTable)
	if f.corruptSigningCRC {
		sigCRC32C = 123456
	}

	return &kmspb.AsymmetricSignResponse{
		Signature:            sigBase64,
		VerifiedDigestCrc32C: verifiedDigestCRC32C,
		SignatureCrc32C:      wrapperspb.Int64(int64(sigCRC32C)),
	}, nil
}

func (f *fakeGoogleKMSClient) GetPublicKey(_ context.Context, req *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
	key, err := f.findKey(req.Name)
	if err != nil {
		return nil, err
	}

	crcTable := crc32.MakeTable(crc32.Castagnoli)
	pemCRC32C := crc32.Checksum([]byte(key.public), crcTable)
	if f.corruptPublicKeyCRC {
		pemCRC32C = 123456
	}
	return &kmspb.PublicKey{
		Pem:       key.public,
		PemCrc32C: wrapperspb.Int64(int64(pemCRC32C)),
	}, nil
}

func (f *fakeGoogleKMSClient) findKey(name string) (*testSigningKey, error) {
	if name == "" {
		return nil, errors.New("missing Name field")
	}
	key, keyFound := availableKMSKeys[name]
	if !keyFound {
		return nil, fmt.Errorf("key %q not found", name)
	}
	return &key, nil
}

func (f *fakeGoogleKMSClient) Close() error {
	return nil
}

type testSigningKey struct {
	private, public string
}
