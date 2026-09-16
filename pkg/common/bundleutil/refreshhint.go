package bundleutil

import (
	"crypto/x509"
	"math"
	"time"

	"github.com/spiffe/spire/proto/spire/common"
)

const (
	refreshHintLeewayFactor = 10

	// MinimumRefreshHint is the smallest refresh hint the client allows.
	// Anything smaller than the minimum will be reset to the minimum.
	MinimumRefreshHint = time.Minute
)

// CalculateRefreshHint is used to calculate the refresh hint for a given
// bundle. If the bundle already contains a refresh hint, then that is used,
// Otherwise, it looks at the lifetimes of the bundle contents and returns a
// fraction of the smallest. It is fairly aggressive but ensures clients don't
// miss a rotation period and lose their ability to fetch.
// TODO: reevaluate our strategy here when we rework the TTL story inside SPIRE.
func CalculateRefreshHint(bundle *common.Bundle) time.Duration {
	if bundle.RefreshHint > 0 {
		return safeRefreshHint(time.Duration(bundle.RefreshHint) * time.Second)
	}

	const maxDuration time.Duration = math.MaxInt64

	smallestLifetime := maxDuration
	for _, rootCA := range bundle.RootCas {
		certs, err := x509.ParseCertificates(rootCA.DerBytes)
		if err != nil {
			continue
		}
		for _, cert := range certs {
			if lifetime := cert.NotAfter.Sub(cert.NotBefore); lifetime < smallestLifetime {
				smallestLifetime = lifetime
			}
		}
	}

	// JWT signing keys have no issuance date, so their remaining validity is
	// used instead, which is never longer than their lifetime.
	now := time.Now()
	for _, jwtSigningKey := range bundle.JwtSigningKeys {
		if jwtSigningKey.NotAfter == 0 {
			continue
		}
		if lifetime := time.Unix(jwtSigningKey.NotAfter, 0).Sub(now); lifetime < smallestLifetime {
			smallestLifetime = lifetime
		}
	}

	// Set the refresh hint to a fraction of the smallest lifetime, if found.
	var refreshHint time.Duration
	if smallestLifetime != maxDuration {
		refreshHint = smallestLifetime / refreshHintLeewayFactor
	}
	return safeRefreshHint(refreshHint)
}

func safeRefreshHint(refreshHint time.Duration) time.Duration {
	if refreshHint < MinimumRefreshHint {
		return MinimumRefreshHint
	}
	return refreshHint
}
