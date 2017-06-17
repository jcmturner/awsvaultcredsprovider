package vault

import (
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/jcmturner/awsvaultcredsprovider/vault"
	"time"
)

const (
	PROVIDER_NAME = "VaultCredsProvider"
)


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
	}, nil
}

func (p *VaultCredsProvider) IsExpired() bool {
	// Setting TTL to <0 will cause the cache to never be used as will always be expired
	if p.Credential.TTL < 0 {
		return true
	}
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
		if ttl, ok := v.(int); ok {
			t := time.Now().UTC().Add(time.Duration(ttl) * time.Second)
			if p.Credential.Expiration.After(t) {
				p.Credential.Expiration = t
			}
		}
	}
	return nil
}
