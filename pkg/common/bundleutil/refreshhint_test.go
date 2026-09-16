package bundleutil

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/require"
)

func TestCalculateRefreshHint(t *testing.T) {
	trustDomainID := "spiffe://domain.test"
	emptyBundle := &common.Bundle{TrustDomainId: trustDomainID}
	emptyBundleWithRefreshHint := &common.Bundle{
		TrustDomainId: trustDomainID,
		RefreshHint:   int64(time.Hour.Seconds()),
	}

	now := time.Now()
	bundleWithCerts := &common.Bundle{
		TrustDomainId: trustDomainID,
		RootCas: []*common.Certificate{
			{DerBytes: createRootCA(t, now, now.Add(time.Hour*2)).Raw},
			{DerBytes: createRootCA(t, now, now.Add(time.Hour)).Raw},
			{DerBytes: createRootCA(t, now, now.Add(time.Hour*3)).Raw},
		},
	}

	pkixBytes, err := x509.MarshalPKIXPublicKey(testKey.Public())
	require.NoError(t, err)

	bundleWithCertsAndJWTKeys := &common.Bundle{
		TrustDomainId: trustDomainID,
		RootCas: []*common.Certificate{
			{DerBytes: createRootCA(t, now, now.Add(time.Hour*3)).Raw},
		},
		JwtSigningKeys: []*common.PublicKey{
			{Kid: "A", PkixBytes: pkixBytes, NotAfter: now.Add(time.Hour).Unix()},
			{Kid: "B", PkixBytes: pkixBytes, NotAfter: now.Add(time.Hour * 2).Unix()},
			{Kid: "C", PkixBytes: pkixBytes},
		},
	}

	testCases := []struct {
		name        string
		bundle      *common.Bundle
		refreshHint time.Duration
	}{
		{
			name:        "empty bundle with no refresh hint",
			bundle:      emptyBundle,
			refreshHint: MinimumRefreshHint,
		},
		{
			name:        "empty bundle with refresh hint",
			bundle:      emptyBundleWithRefreshHint,
			refreshHint: time.Hour,
		},
		{
			// the bundle has a few certs. the lowest lifetime is 1 hour.
			// so we expect to get back a fraction of that time.
			name:        "bundle with certs",
			bundle:      bundleWithCerts,
			refreshHint: time.Hour / refreshHintLeewayFactor,
		},
		{
			// the JWT signing key that expires in 1 hour expires before the
			// root CA, so the refresh hint follows the key instead. the key
			// without an expiration is ignored.
			name:        "bundle with certs and JWT signing keys",
			bundle:      bundleWithCertsAndJWTKeys,
			refreshHint: time.Hour / refreshHintLeewayFactor,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.InDelta(t, float64(testCase.refreshHint), float64(CalculateRefreshHint(testCase.bundle)), float64(time.Second), "refresh hint is wrong")
		})
	}
}

func createRootCA(t *testing.T, notBefore, notAfter time.Time) *x509.Certificate {
	return createCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		IsCA:         true,
	})
}
