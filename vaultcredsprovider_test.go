package vault

import (
	"github.com/jcmturner/awsvaultcredsprovider/vault"
	"github.com/jcmturner/restclient"
	"github.com/jcmturner/vaultmock"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

const (
	Test_SecretAccessKey = "9drTJvcXLB89EXAMPLELB8923FB892xMFI"
	Test_SessionToken    = "AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU="
	Test_Expiration      = "2016-03-15T00:05:07Z"
	Test_AccessKeyId     = "ASIAJEXAMPLEXEG2JICEA"
	Test_SecretsPath     = "/secret/awskeys/"
	Test_Arn             = "arn:aws:iam::123456789012:user/test"
)

func TestVaultCredsProvider_StoreAndReadBack(t *testing.T) {
	s, addr, certPool, test_app_id, test_user_id := vaultmock.RunMockVault(t)
	defer s.Close()
	c := restclient.NewConfig().WithEndPoint(addr).WithCACertPool(certPool)
	vconf := vault.Config{
		SecretsPath:      Test_SecretsPath,
		ReSTClientConfig: *c,
	}
	vcreds := vault.Credentials{
		UserID: test_user_id,
		AppID:  test_app_id,
	}
	p, err := NewVaultCredsProvider(Test_Arn, vconf, vcreds)
	if err != nil {
		t.Fatalf("Error creating VaultCredsProvider: %v", err)
	}

	xt, err := time.Parse(time.RFC3339, Test_Expiration)
	if err != nil {
		t.Logf("Error parsing test expiry time: %v", err)
	}
	cred := AWSCredential{
		SecretAccessKey: Test_SecretAccessKey,
		SessionToken:    Test_SessionToken,
		AccessKeyId:     Test_AccessKeyId,
		Expiration:      xt,
	}
	p.Credential = cred

	// Store
	err = p.Store()
	if err != nil {
		t.Fatalf("Failed to store AWS credential: %v", err)
	}

	// Read back
	pr, err := NewVaultCredsProvider(Test_Arn, vconf, vcreds)
	if err != nil {
		t.Fatalf("Error creating VaultCredsProvider for read: %v", err)
	}
	err = pr.Read()
	if err != nil {
		t.Fatalf("Failed to store AWS credential: %v", err)
	}
	assert.Equal(t, cred.AccessKeyId, pr.Credential.AccessKeyId, "AccessKeyId not as expected")
	assert.Equal(t, cred.Expiration, pr.Credential.Expiration, "Expiration not as expected")
	assert.Equal(t, cred.SessionToken, pr.Credential.SessionToken, "SessionToken not as expected")
	assert.Equal(t, cred.SecretAccessKey, pr.Credential.SecretAccessKey, "SecretAccessKey not as expected")
}
