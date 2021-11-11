package artifact

import (
	"context"
	"encoding/asn1"
	"encoding/base64"
	"hash/crc32"
	"math/big"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	gax "github.com/googleapis/gax-go/v2"
	"github.com/minio/sha256-simd"
	"github.com/pkg/errors"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// NewGoogleKMSSigner creates a Signer that signs using a key from
// Google Cloud's Key Management Service.
// Release resources by calling Close().
func NewGoogleKMSSigner(ctx context.Context, name string) (*GoogleKMS, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "signer: error connecting to KMS")
	}

	return &GoogleKMS{
		name:       name,
		client:     client,
		rpcTimeout: 60 * time.Second,
	}, nil
}

type GoogleKMS struct {
	name       string
	client     googleKMSClient
	rpcTimeout time.Duration
}

func (k *GoogleKMS) Sign(message []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.TODO(), k.rpcTimeout)
	defer cancel()

	// Although we don't need this verify method, we use this to
	// check that the key fits our supported algorithms. When
	// performing the actual signature, there's no way to actually
	// check the key's algorithm.
	sm, err := k.getKMSKeyAndVerifyMethod(ctx)
	if err != nil {
		return nil, err
	}

	h := sha256.Sum256(message)

	digestBase64 := make([]byte, base64.StdEncoding.EncodedLen(len(h)))
	base64.StdEncoding.Encode(digestBase64, h[:])

	digestCRC32C := checksum(digestBase64)

	result, err := k.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: k.name,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digestBase64,
			},
		},
		DigestCrc32C: wrapperspb.Int64(digestCRC32C),
	})
	if err != nil {
		return nil, errors.Wrap(err, "signer: error signing image with KMS")
	}
	if !result.VerifiedDigestCrc32C {
		return nil, errors.New("signer: KMS signing request corrupted")
	}
	if checksum(result.Signature) != result.SignatureCrc32C.Value {
		return nil, errors.New("signer: KMS signing response corrupted")
	}

	sig := make([]byte, base64.StdEncoding.DecodedLen(len(result.Signature)))
	base64.StdEncoding.Decode(sig, result.Signature)

	switch sm.method.(type) {
	case *RSA:
		return result.Signature, nil
	case *ECDSA256:
		// KMS serializes ECDSA keys in ASN1 format. Convert it back into our own format.
		var parsedSig struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(sig, &parsedSig); err != nil {
			return nil, errors.Wrap(err, "signer: failed to parse ECDSA signature")
		}
		marshaledSigBytes, err := marshalECDSASignature(parsedSig.R, parsedSig.S)
		if err != nil {
			return nil, err
		}
		outputSig := make([]byte, base64.StdEncoding.EncodedLen(len(marshaledSigBytes)))
		base64.StdEncoding.Encode(outputSig, marshaledSigBytes)
		return outputSig, nil
	default:
		return nil, errors.New("signer: unsupported algorithm")
	}
}

func (k *GoogleKMS) Verify(message, sig []byte) error {
	ctx, cancel := context.WithTimeout(context.TODO(), k.rpcTimeout)
	defer cancel()

	sm, err := k.getKMSKeyAndVerifyMethod(ctx)
	if err != nil {
		return err
	}

	dec := make([]byte, base64.StdEncoding.DecodedLen(len(sig)))
	decLen, err := base64.StdEncoding.Decode(dec, sig)
	if err != nil {
		return errors.Wrap(err, "signer: error decoding signature")
	}

	return sm.method.Verify(message, dec[:decLen], sm.key)
}

func (k *GoogleKMS) getKMSKeyAndVerifyMethod(ctx context.Context) (*SigningMethod, error) {
	response, err := k.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: k.name})
	if err != nil {
		return nil, errors.Wrap(err, "signer: error getting public key from KMS")
	}

	if checksum([]byte(response.Pem)) != response.PemCrc32C.Value {
		return nil, errors.New("signer: KMS verification response corrupted")
	}

	return getKeyAndVerifyMethod([]byte(response.Pem))
}

func (k *GoogleKMS) Close() error {
	return k.client.Close()
}

func checksum(data []byte) int64 {
	crcTable := crc32.MakeTable(crc32.Castagnoli)
	return int64(crc32.Checksum(data, crcTable))
}

type googleKMSClient interface {
	AsymmetricSign(context.Context, *kmspb.AsymmetricSignRequest, ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
	GetPublicKey(context.Context, *kmspb.GetPublicKeyRequest, ...gax.CallOption) (*kmspb.PublicKey, error)
	Close() error
}
