package vault

import (
	"encoding/json"
	"fmt"
	vaultAPI "github.com/hashicorp/vault/api"
	"github.com/jcmturner/restclient"
	"io/ioutil"
)

// Client struct.
type Client struct {
	credentials *Credentials
	config      *Config
	session     *Session
}

type Credentials struct {
	AppID      string `json:"AppID"`
	UserID     string `json:"UserID"`
	UserIDFile string `json:"UserIDFile"`
}

type UserIdFile struct {
	UserID string `json:"UserID"`
}

type Config struct {
	APIConfig        *vaultAPI.Config
	APIClient        *vaultAPI.Client
	SecretsPath      *string            `json:"SecretsPath"`
	ReSTClientConfig *restclient.Config `json:"VaultConnection"`
}

func (creds *Credentials) ReadUserID() error {
	j, err := ioutil.ReadFile(creds.UserIDFile)
	if err != nil {
		return fmt.Errorf("Could not open UserId file at %s: %v", creds.UserIDFile, err)
	}
	var uf UserIdFile
	err = json.Unmarshal(j, &uf)
	if err != nil {
		return fmt.Errorf("UserId file could not be parsed: %v", err)
	}
	creds.UserID = uf.UserID
	return nil
}

func NewClient(conf *Config, creds *Credentials) (Client, error) {
	if creds.UserID == "" && creds.UserIDFile != "" {
		creds.ReadUserID()
	}
	var s Session
	err := s.NewRequest(conf.ReSTClientConfig, creds.AppID, creds.UserID)
	if err != nil {
		return Client{}, fmt.Errorf("Error creating Vault login request object: %v", err)
	}
	token, err := s.GetToken()
	if err != nil {
		return Client{}, fmt.Errorf("Error getting login token to the Vault: %v", err)
	}
	vc, err := vaultAPI.NewClient(conf.APIConfig)
	if err != nil {
		return Client{}, fmt.Errorf("Unable to create Vault client: %v", err)
	}
	vc.SetToken(token)
	return Client{
		credentials: creds,
		config:      conf,
		session:     &s,
	}, nil
}

func (c *Client) Read(p string) (map[string]interface{}, error) {
	m := make(map[string]interface{})
	// Refresh the access token to the vault is needs be
	token, err := c.session.GetToken()
	if err != nil {
		return m, fmt.Errorf("Error getting login token to the Vault: %v", err)
	}
	c.config.APIClient.SetToken(token)
	logical := c.config.APIClient.Logical()
	s, err := logical.Read(*c.config.SecretsPath + p)
	if err != nil {
		return m, fmt.Errorf("Issue when reading secret from Vault at %s: %v", *c.config.SecretsPath+p, err)
	}
	if s == nil {
		return nil, err
	}
	return s.Data, err
}

func (c *Client) Write(p string, m map[string]interface{}) error {
	// Refresh the access token to the vault is needs be
	token, err := c.session.GetToken()
	if err != nil {
		return fmt.Errorf("Error getting login token to the Vault: %v", err)
	}
	c.config.APIClient.SetToken(token)
	logical := c.config.APIClient.Logical()
	_, err = logical.Write(*c.config.SecretsPath+p, m)
	return err
}
