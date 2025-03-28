package gcpss

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"cloud.google.com/go/compute/metadata"
	"github.com/BESTSELLER/go-vault/models"
)

func fetchJWT(vaultRole string) (jwt string, err error) {
	client := metadata.NewClient(http.DefaultClient)
	return client.GetWithContext(context.Background(), "instance/service-accounts/default/identity?audience=http://vault/" + vaultRole + "&format=full")
}

func fetchVaultToken(vaultAddr string, jwt string, vaultRole string) (vaultToken string, err error) {
	login, err := fetchVaultLogin(vaultAddr, jwt, vaultRole)

	if err != nil {
		return "", err
	}

	return login.Auth.ClientToken, nil
}

func fetchVaultLogin(vaultAddr string, jwt string, vaultRole string) (models.Login, error) {
	client := http.DefaultClient

	j := `{"role":"` + vaultRole + `", "jwt":"` + jwt + `"}`

	req, err := http.NewRequest(http.MethodPost, vaultAddr+"/v1/auth/gcp/login", bytes.NewBufferString(j))
	if err != nil {
		return models.Login{}, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return models.Login{}, err
	}
	defer resp.Body.Close()

	var login models.Login

	err = json.NewDecoder(resp.Body).Decode(&login)
	if err != nil {
		return models.Login{}, err
	}

	if len(login.Errors) > 0 {
		return models.Login{}, fmt.Errorf(login.Errors[0])
	}
	if login.Auth.ClientToken == "" {
		return models.Login{}, fmt.Errorf("unable to retrieve vault token")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 202 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return models.Login{}, err
		}
		return models.Login{}, fmt.Errorf("request failed, expected status: 2xx got: %d, error message %s", resp.StatusCode, string(body))
	}

	return login, nil
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
		body, err := io.ReadAll(resp.Body)
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
	if err != nil {
		return "", err
	}

	data, err := readSecret(vaultAddr, token, vaultSecret)
	if err != nil {
		return "", err
	}
	return data, nil
}
