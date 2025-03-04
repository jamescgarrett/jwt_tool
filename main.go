package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

type Config struct {
	// Custom
	Custom struct {
		Claims             jwt.MapClaims      `json:"claims,omitempty"`
		Header             map[string]*string `json:"header,omitempty"`
		WellKnownEndpoint  *string            `json:"well_known_endpoint,omitempty"`
		JWKLocal           bool               `json:"jwk_local,omitempty"`
		JWKLocalFile       string             `json:"jwk_local_file,omitempty"`
		PrivateKeyFilePath *string            `json:"private_key_file_path,omitempty"`
	}
	// RS
	RS struct {
		SetupRS      bool    `json:"setup_rs,omitempty"`
		Domain       *string `json:"domain,omitempty"`
		ClientID     *string `json:"client_id,omitempty"`
		ClientSecret *string `json:"client_secret,omitempty"`
		Username     *string `json:"username,omitempty"`
		Password     *string `json:"password,omitempty"`
	}
	UseRS bool `json:"use_rs,omitempty"`
	Debug bool `json:"debug,omitempty"`
}

func prettyJSONLog(description string, details []byte) error {
	var prettyJSON bytes.Buffer
	err := json.Indent(&prettyJSON, details, "", "   ")
	if err != nil {
		return errors.New(fmt.Sprintf("%v: \nMESSAGE: %s", err, string(details)))
	}

	detailsString := fmt.Sprintf("\033[34m%s\033[0m", prettyJSON.String())
	fmt.Print(fmt.Sprintf("%s:\n%s", description, detailsString))

	return nil
}

func parseConfig(configFile string) (*Config, error) {
	if configFile == "" {
		return nil, errors.New("a configFile is required")
	}

	file, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	var config Config
	err = json.Unmarshal(file, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func main() {
	configFile := flag.String("configFile", "config.json", "File containing config")
	flag.Parse()

	config, err := parseConfig(*configFile)
	if err != nil {
		fmt.Print(fmt.Sprintf("\033[31;1m %v \033[0m", err))
	}

	if !config.UseRS {
		token, err := handleCustomToken(HandleCustomTokenParams{
			Config: *config,
		})
		if err != nil {
			fmt.Print(fmt.Sprintf("\033[31;1m %v \033[0m", err))
		}
		fmt.Print(fmt.Sprintf("ACCESS TOKEN:\n\033[32;1m%s\033[0m", *token))
		return
	}

	token, err := handleRSToken(HandleRSTokenParams{
		Config: *config,
	})
	if err != nil {
		fmt.Print(fmt.Sprintf("\033[31;1m %v \033[0m", err))
	}
	fmt.Print(fmt.Sprintf("\n\nACCESS TOKEN:\n\033[32;1m%s\033[0m", string(token.AccessToken)))
}
