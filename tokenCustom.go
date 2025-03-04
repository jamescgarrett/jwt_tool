package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/jwk"
)

type HandleCustomTokenParams struct {
	Config Config
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

func checkCustomConfig(config Config) error {
	if config.Custom.PrivateKeyFilePath == nil {
		return errors.New("iss claim is required in your config json file")
	}
	if config.Custom.Claims["iss"] == nil {
		return errors.New("iss claim is required in your config json file")
	}
	if config.Custom.Claims["iss"] == nil {
		return errors.New("iss claim is required in your config json file")
	}
	if config.Custom.Claims["aud"] == nil {
		return errors.New("aud claim is required in your config json file")
	}
	if config.Custom.Claims["sub"] == nil {
		return errors.New("sub claim is required in your config json file")
	}
	if config.Custom.Claims["client_id"] == nil {
		return errors.New("client_id claim is required in your config json file")
	}
	if config.Custom.WellKnownEndpoint == nil {
		return errors.New("wk_path claim is required in your config json file")
	}

	return nil
}

func handleCustomToken(params HandleCustomTokenParams) (*string, error) {
	err := checkCustomConfig(params.Config)
	if err != nil {
		return nil, err
	}

	tokenString, err := createToken(CreateTokenParams{
		Claims:             params.Config.Custom.Claims,
		Headers:            params.Config.Custom.Header,
		PrivateKeyFilePath: *params.Config.Custom.PrivateKeyFilePath,
		WellKnownEndpoint:  *params.Config.Custom.WellKnownEndpoint,
		JWKFile:            params.Config.Custom.JWKLocalFile,
		Debug:              params.Config.Debug,
	})
	if err != nil {
		return nil, err
	}

	return &tokenString, nil
}
