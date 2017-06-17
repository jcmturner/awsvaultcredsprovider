package vault

import (
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/jcmturner/awsvaultcredsprovider/vault"
	"time"
)

const (
	PROVIDER_NAME = "VaultCredsProvider"
)

//{
//"SecretAccessKey": "9drTJvcXLB89EXAMPLELB8923FB892xMFI",
//"SessionToken": "AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU=",
//"Expiration": "2016-03-15T00:05:07Z",
//"AccessKeyId": "ASIAJEXAMPLEXEG2JICEA"
//}
type AWSCredential struct {
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
	TTL             int
}

type VaultCredsProvider struct {
	VaultClient *vault.Client
	Arn         string
	Credential  AWSCredential
}

func (p *VaultCredsProvider) Retrieve() (credentials.Value, error) {
	err := p.Read()
	if err != nil {
		return credentials.Value{}, err
	}
	return credentials.Value{
		AccessKeyID:     p.Credential.AccessKeyId,
		SecretAccessKey: p.Credential.SecretAccessKey,
		SessionToken:    p.Credential.SessionToken,
		ProviderName:    PROVIDER_NAME,
	}

}

func (p *VaultCredsProvider) IsExpired() bool {
	if time.Now().UTC().After(p.Credential.Expiration) {
		return true
	}
	return false
}

func (p *VaultCredsProvider) Store(arn string) error {
	m := map[string]interface{}{
		"AccessKeyID":     p.Credential.AccessKeyId,
		"SecretAccessKey": p.Credential.SecretAccessKey,
		"SessionToken":    p.Credential.SessionToken,
		"Expiration":      p.Credential.Expiration,
		"TTL":             p.Credential.TTL,
	}
	return p.VaultClient.Write(arn, m)
}

func (p *VaultCredsProvider) Read() error {
	m, err := p.VaultClient.Read(p.Arn)
	if err != nil {
		return err
	}
	if v, ok := m["AccessKeyID"]; ok {
		p.Credential.AccessKeyId = v.(string)
	}
	if v, ok := m["SecretAccessKey"]; ok {
		p.Credential.SecretAccessKey = v.(string)
	}
	if v, ok := m["SessionToken"]; ok {
		p.Credential.SessionToken = v.(string)
	}
	if v, ok := m["Expiration"]; ok {
		p.Credential.Expiration = v.(time.Time)
	}
	if v, ok := m["TTL"]; ok {
		if v.(int) && v.(int) > 0 {
			t := time.Now().UTC().Add(time.Duration(v.(int)) * time.Second)
			if p.Credential.Expiration.After(t) {
				p.Credential.Expiration = t
			}
		}
	}
	return nil
}
