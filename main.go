package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/jwk"
)

type Config struct {
	Claims            jwt.MapClaims      `json:"claims"`
	Header            map[string]*string `json:"header"`
	WellKnownEndpoint *string            `json:"well_known_endpoint"`
	JWKLocal          bool               `json:"jwk_local"`
}

type JWKSet struct {
	KTY string `json:"kty"`
	USE string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	KID string `json:"kid"`
	X5T string `json:"x5t"`
	X5C string `json:"x5c"`
	ALG string `json:"alg"`
}

type JWKSets struct {
	Keys []JWKSet `json:"keys"`
}

type CreateTokenParams struct {
	Claims             jwt.MapClaims
	Headers            map[string]*string
	PrivateKeyFilePath string
	WellKnownEndpoint  string
	JWKFile            string
	Debug              bool
}

type GetJWKSetParams struct {
	WellKnownEndpoint string
	JWKFile           string
	KID               *string
	Debug             bool
}

func prettyJSONLog(description string, details []byte) error {
	var prettyJSON bytes.Buffer
	err := json.Indent(&prettyJSON, details, "", "   ")
	if err != nil {
		return err
	}

	detailsString := fmt.Sprintf("\033[34m%s\033[0m", prettyJSON.String())
	fmt.Print(fmt.Sprintf("%s:\n%s", description, detailsString))

	return nil
}

func generateJTI() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func getJwkSet(params *GetJWKSetParams) ([]byte, error) {
	useLocalJWK := params.JWKFile != ""

	var jwkJSON []byte
	var err error

	if useLocalJWK {
		jwkJSON, err = os.ReadFile(params.JWKFile)
		if err != nil {
			return nil, err
		}
	} else {
		jwkResponse, err := http.Get(params.WellKnownEndpoint)
		if err != nil {
			return nil, err
		}

		jwkJSON, err = io.ReadAll(jwkResponse.Body)
		if err != nil {
			return nil, err
		}
	}

	if params.Debug {
		err := prettyJSONLog("DEBUG JWK RESPONSE", jwkJSON)
		if err != nil {
			return nil, err
		}
	}

	jwkSet, err := jwk.Parse(jwkJSON)
	if err != nil {
		return nil, err
	}

	var jwkKey jwk.Key
	var ok bool
	if params.KID != nil {
		jwkKey, ok = jwkSet.LookupKeyID(*params.KID)
		if !ok {
			fmt.Print(fmt.Sprintf("\n\nCould not find key with kid: %s. Attempting to use first key from response instead.\n\n", *params.KID))
			jwkKey, ok = jwkSet.Get(0)
			if !ok {
				return nil, errors.New("There was trouble finding a key from the JWK set")
			}
		}
	} else {
		jwkKey, ok = jwkSet.Get(0)
		if !ok {
			return nil, errors.New("There was trouble finding a key from the JWK set")
		}
	}

	var rawKey rsa.PublicKey
	if err := jwkKey.Raw(&rawKey); err != nil {
		return nil, err
	}

	der := x509.MarshalPKCS1PublicKey(&rawKey)

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}

	pemData := pem.EncodeToMemory(pemBlock)

	return pemData, nil
}

func verifyToken(tokenString string, publicKey []byte) (*jwt.Token, error) {
	parsedPublicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New(fmt.Sprintf("unexpected signing method: %v", token.Header["alg"]))
		}
		return parsedPublicKey, nil
	})

	if err != nil {
		return nil, err
	}

	return token, nil
}

func createToken(params CreateTokenParams) (string, error) {
	if params.Claims["exp"] == nil {
		params.Claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	}

	if params.Claims["iat"] == nil {
		params.Claims["iat"] = time.Now().Unix()
	}

	if params.Claims["jti"] == nil {
		jti, err := generateJTI()
		if err != nil {
			return "", errors.New(fmt.Sprintf("ERROR: createToken:generateJTI: %v", err))
		}
		params.Claims["jti"] = jti
	}

	privateKeyFile, err := os.ReadFile(params.PrivateKeyFilePath)
	if err != nil {
		return "", errors.New(fmt.Sprintf("ERROR: createToken:ReadFile: %v", err))
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyFile)
	if err != nil {
		return "", errors.New(fmt.Sprintf("ERROR: createToken:ParseRSAPrivateKeyFromPEM: %v", err))
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, params.Claims)
	if params.Headers["kid"] != nil {
		token.Header["kid"] = params.Headers["kid"]
	}

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", errors.New(fmt.Sprintf("ERROR: createToken:SignedString: %v", err))
	}

	publicKey, err := getJwkSet(&GetJWKSetParams{
		WellKnownEndpoint: params.WellKnownEndpoint,
		JWKFile:           params.JWKFile,
		KID:               params.Headers["kid"],
		Debug:             params.Debug,
	})
	if err != nil {
		return "", errors.New(fmt.Sprintf("ERROR: getJwkSet: %v", err))
	}

	verifiedToken, err := verifyToken(tokenString, publicKey)
	if err != nil {
		return "", errors.New(fmt.Sprintf("ERROR: verifyToken: %v", err))
	}

	if params.Debug {
		debugData, err := json.MarshalIndent(verifiedToken, "", "  ")
		if err != nil {
			return "", errors.New(fmt.Sprintf("ERROR: MarshalIndent: %v", err))
		}
		fmt.Print("DEBUG VERIFIED TOKEN:\n\033[34m", string(debugData), "\033[0m\n\n")
	}

	return tokenString, nil
}

func checkConfig(configFile *string) (*Config, error) {
	if configFile == nil {
		return nil, errors.New("a configFile is required")
	}

	file, err := os.ReadFile(*configFile)
	if err != nil {
		return nil, err
	}

	var config Config
	err = json.Unmarshal(file, &config)
	if err != nil {
		return nil, err
	}

	if config.Claims["iss"] == nil {
		return nil, errors.New("iss claim is required in your config json file")
	}
	if config.Claims["aud"] == nil {
		return nil, errors.New("aud claim is required in your config json file")
	}
	if config.Claims["sub"] == nil {
		return nil, errors.New("sub claim is required in your config json file")
	}
	if config.Claims["client_id"] == nil {
		return nil, errors.New("client_id claim is required in your config json file")
	}
	if config.WellKnownEndpoint == nil {
		return nil, errors.New("wk_path claim is required in your config json file")
	}

	return &config, nil
}

func main() {
	configFile := flag.String("configFile", "claims.json", "File containing required claims")
	privateKeyFilePath := flag.String("privateKeyFile", "private_key.pem", "File containing private key")
	jwkFile := flag.String("jwkFile", "", "Local file containing JWK key sets")
	debug := flag.Bool("debug", false, "Use for show debug logs")
	flag.Parse()

	if privateKeyFilePath == nil {
		fmt.Print("\033[31;1m a privateKeyFile file is required \033[0m")
		return
	}

	config, err := checkConfig(configFile)
	if err != nil {
		fmt.Print(fmt.Sprintf("\033[31;1m %v \033[0m", err))
	}

	tokenString, err := createToken(CreateTokenParams{
		Claims:             config.Claims,
		Headers:            config.Header,
		PrivateKeyFilePath: *privateKeyFilePath,
		WellKnownEndpoint:  *config.WellKnownEndpoint,
		JWKFile:            *jwkFile,
		Debug:              *debug,
	})
	if err != nil {
		fmt.Print(fmt.Sprintf("\033[31;1m %v \033[0m", err))
		return
	}

	fmt.Print(fmt.Sprintf("ACCESS TOKEN:\n\033[32;1m%s\033[0m", tokenString))
}
