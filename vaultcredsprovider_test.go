package vault

import (
	"testing"
	"time"
)

const (
	Test_SecretAccessKey = "9drTJvcXLB89EXAMPLELB8923FB892xMFI"
	Test_SessionToken    = "AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU="
	Test_Expiration      = "2016-03-15T00:05:07Z"
	Test_AccessKeyId     = "ASIAJEXAMPLEXEG2JICEA"
)

func TestVaultCredsProvider_Store(t *testing.T) {
	xt, err := time.Parse(time.RFC3339, Test_Expiration)
	if err != nil {
		t.Logf("Error parsing test expiry time: %v", err)
	}
	cred := AWSCredential{
		SecretAccessKey: Test_SecretAccessKey,
		SessionToken: Test_SessionToken,
		AccessKeyId: Test_AccessKeyId,
		Expiration: xt,
	}
	t.Logf("cred; %+v", cred)
}
