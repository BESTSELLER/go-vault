package gcpss

import (
	"bytes"
	"cloud.google.com/go/compute/metadata"
	"encoding/json"
	"fmt"
	"github.com/BESTSELLER/go-vault/models"
	"io/ioutil"
	"net/http"
)

func fetchJWT(vaultRole string) (jwt string, err error) {
	client := metadata.NewClient(http.DefaultClient)
	return client.Get("instance/service-accounts/default/identity?audience=http://vault/" + vaultRole + "&format=full")
}

func fetchVaultToken(vaultAddr string, jwt string, vaultRole string) (vaultToken string, err error) {
	client := http.DefaultClient

	j := `{"role":"` + vaultRole + `", "jwt":"` + jwt + `"}`

	req, err := http.NewRequest(http.MethodPost, vaultAddr+"/v1/auth/gcp/login", bytes.NewBufferString(j))
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var s models.Login

	err = json.NewDecoder(resp.Body).Decode(&s)
	if err != nil {
		return "", err
	}

	if len(s.Errors) > 0 {
		return "", fmt.Errorf(s.Errors[0])
	}
	if s.Auth.ClientToken == "" {
		return "", fmt.Errorf("unable to retrieve vault token")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 202 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		return "", fmt.Errorf("request failed, expected status: 2xx got: %d, error message %s", resp.StatusCode, string(body))
	}

	return s.Auth.ClientToken, nil
}

func readSecret(vaultAddr string, vaultToken string, vaultSecret string) (secret string, err error) {
	client := http.DefaultClient
	req, err := http.NewRequest(http.MethodGet, vaultAddr+"/v1/"+vaultSecret, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Vault-Token", vaultToken)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var s models.Data

	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return "", err
	}

	data, err := json.Marshal(s.Data.Data)
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 202 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		return "", fmt.Errorf("request failed, expected status: 2xx got: %d, error message %s", resp.StatusCode, string(body))
	}

	return string(data), nil
}

// FetchVaultToken gets Workload Identity Token from GCP Metadata API and uses it to fetch Vault Token.
func FetchVaultToken(vaultAddr string, vaultRole string) (vaultToken string, err error) {
	jwt, err := fetchJWT(vaultRole)
	if err != nil {
		return "", err
	}

	token, err := fetchVaultToken(vaultAddr, jwt, vaultRole)
	if err != nil {
		return "", err
	}

	return token, nil
}

// FetchVaultSecret returns secret from Hashicorp Vault.
func FetchVaultSecret(vaultAddr string, vaultSecret string, vaultRole string) (secret string, err error) {
	token, err := FetchVaultToken(vaultAddr, vaultRole)

	data, err := readSecret(vaultAddr, token, vaultSecret)
	if err != nil {
		return "", err
	}
	return data, nil
}
