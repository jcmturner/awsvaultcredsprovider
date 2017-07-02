package awsvaultcredsprovider

import (
	"context"
	"crypto/sha1"
	"encoding/json"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/jcmturner/awsvaultcredsprovider/vault"
	"github.com/jcmturner/gootp"
	"time"
	"fmt"
	"os"
)

const (
	PROVIDER_NAME = "VaultCredsProvider"
	DefaultTempCredentialsDuration = 900
)

type AWSCredential struct {
	AccessKeyId     string
	secretAccessKey string
	sessionToken    string
	mFASerialNumber string
	mFASecret       string
	Expiration      time.Time
	TTL             int64
}

type VaultCredsProvider struct {
	VaultClient *vault.Client
	Arn         string
	Credential  AWSCredential
}

func NewVaultCredsProvider(arn string, conf vault.Config, creds vault.Credentials) (*VaultCredsProvider, error) {
	cl, err := vault.NewClient(&conf, &creds)
	if err != nil {
		return nil, err
	}
	return &VaultCredsProvider{
		VaultClient: &cl,
		Arn:         arn,
	}, nil
}

func (p *VaultCredsProvider) SetAccessKey(s string) *VaultCredsProvider {
	p.Credential.AccessKeyId = s
	return p
}

func (p *VaultCredsProvider) SetSecretAccessKey(s string) *VaultCredsProvider {
	p.Credential.secretAccessKey = s
	return p
}

func (p *VaultCredsProvider) SetSessionToken(s string) *VaultCredsProvider {
	p.Credential.sessionToken = s
	return p
}

func (p *VaultCredsProvider) SetExpiration(t time.Time) *VaultCredsProvider {
	p.Credential.Expiration = t
	return p
}

func (p *VaultCredsProvider) SetTTL(ttl int64) *VaultCredsProvider {
	p.Credential.TTL = ttl
	return p
}

func (p *VaultCredsProvider) WithMFA(serial, secret string) *VaultCredsProvider {
	p.Credential.mFASerialNumber = serial
	p.Credential.mFASecret = secret
	return p
}

func (p *VaultCredsProvider) Retrieve() (credentials.Value, error) {
	err := p.Read()
	if err != nil {
		return credentials.Value{}, err
	}
	if p.Credential.mFASecret != "" && p.Credential.mFASerialNumber != "" {
		// We have an MFA so we will get a session to be able to support calls where MFA is required.
		err := p.getSessionCredentials()
		if err != nil {
			return credentials.Value{}, err
		}
	}
	return credentials.Value{
		AccessKeyID:     p.Credential.AccessKeyId,
		SecretAccessKey: p.Credential.secretAccessKey,
		SessionToken:    p.Credential.sessionToken,
		ProviderName:    PROVIDER_NAME,
	}, nil
}

func (p *VaultCredsProvider) getSessionCredentials() error {
	creds := credentials.NewStaticCredentials(p.Credential.AccessKeyId, p.Credential.secretAccessKey, p.Credential.sessionToken)
	config := aws.NewConfig().WithCredentials(creds)
	sess := session.Must(session.NewSession(config))
	svc := sts.New(sess)

	ctx := context.Background()

	OTP, _, err := gootp.GetTOTPNow(p.Credential.mFASecret, sha1.New, 6)
	if err != nil {
		return err
	}

	params := &sts.GetSessionTokenInput{}
	var d int64 = DefaultTempCredentialsDuration
	if p.Credential.TTL > d {
		d = p.Credential.TTL
	}
	params.SetDurationSeconds(d).
		SetSerialNumber(p.Credential.mFASerialNumber).
		SetTokenCode(OTP)
	result, err := svc.GetSessionTokenWithContext(ctx, params)
	if err != nil {
		return err
	}
	p.Credential.AccessKeyId = *result.Credentials.AccessKeyId
	p.Credential.secretAccessKey = *result.Credentials.SecretAccessKey
	p.Credential.sessionToken = *result.Credentials.SessionToken
	p.Credential.Expiration = *result.Credentials.Expiration
	if p.Credential.TTL < 30 {
		// Cannot reuse OTP within 30 seconds. Min of 30s cache
		p.Credential.TTL = 30
	}
	return nil
}

func (p *VaultCredsProvider) IsExpired() bool {
	// Setting TTL to <0 will cause the cache to never be used as will always be expired
	if p.Credential.TTL < 0 {
		fmt.Fprintf(os.Stderr, "Expired TTL: %v\n", p.Credential.TTL)
		return true
	}
	if time.Now().UTC().After(p.Credential.Expiration) {
		fmt.Fprintf(os.Stderr, "Expired: %v\n", p.Credential.Expiration)
		return true
	}
	return false
}

func (p *VaultCredsProvider) Store() error {
	m := map[string]interface{}{
		"AccessKeyID":     p.Credential.AccessKeyId,
		"SecretAccessKey": p.Credential.secretAccessKey,
		"SessionToken":    p.Credential.sessionToken,
		"MFASerialNumber": p.Credential.mFASerialNumber,
		"MFASecret":       p.Credential.mFASecret,
		"Expiration":      p.Credential.Expiration,
		"TTL":             p.Credential.TTL,
	}
	return p.VaultClient.Write(p.Arn, m)
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
		p.Credential.secretAccessKey = v.(string)
	}
	if v, ok := m["SessionToken"]; ok {
		p.Credential.sessionToken = v.(string)
	}
	if v, ok := m["MFASerialNumber"]; ok {
		p.Credential.mFASerialNumber = v.(string)
	}
	if v, ok := m["MFASecret"]; ok {
		p.Credential.mFASecret = v.(string)
	}
	if v, ok := m["Expiration"]; ok {
		if p.Credential.Expiration, err = time.Parse(time.RFC3339, v.(string)); err != nil {
			p.Credential.Expiration = time.Now().UTC()
		}
	}
	if v, ok := m["TTL"]; ok {
		if p.Credential.TTL, err = v.(json.Number).Int64(); err != nil {
			// Default to never caching
			p.Credential.TTL = -1
		}
		t := time.Now().UTC().Add(time.Duration(p.Credential.TTL) * time.Second)
		if p.Credential.Expiration.After(t) || p.Credential.Expiration.IsZero() {
			p.Credential.Expiration = t
		}
	}
	return nil
}
