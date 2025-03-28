package main

import (
	"fmt"
	"log"
	"os"

	"github.com/BESTSELLER/go-vault/gcpss"
)

func main() {
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		log.Fatal("VAULT_ADDR must be set.")
	}
	vaultSecret := os.Getenv("VAULT_SECRET")
	if vaultSecret == "" {
		log.Fatal("VAULT_SECRET must be set.")
	}
	vaultRole := os.Getenv("VAULT_ROLE")
	if vaultRole == "" {
		log.Fatal("VAULT_ROLE must be set.")
	}

	secret, err := gcpss.FetchVaultSecret(vaultAddr, vaultSecret, vaultRole)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(secret)
	data := []byte(secret)
	err = os.WriteFile("/secrets/secrets", data, 0644)
	if err != nil {
		fmt.Println(err)
	}
}
