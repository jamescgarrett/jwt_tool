package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type HandleRSTokenParams struct {
	Config Config
}

type OauthTokenResponse struct {
	AccessToken      string `json:"access_token"`
	Scope            string `json:"scope"`
	ExpiresIn        int    `json:"expires_in"`
	TokenType        string `json:"token_type"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

type RequestHeaders struct {
	ContentType   string
	Authorization string
}

type ExecuteHttpPostRequestParams struct {
	Payload *strings.Reader
	URL     string
	Headers RequestHeaders
	Debug   bool
}

type API2PostResponse struct {
	StatusCode int    `json:"statusCode"`
	Error      string `json:"error"`
	Message    string `json:"message"`
	ErrorCode  string `json:"errorCode"`
}

type MGMTAPIRequestParams struct {
	ClientID           string
	ClientSecret       string
	Domain             string
	Username           string
	Password           string
	OauthTokenResponse OauthTokenResponse
	Debug              bool
}

func executeHttpPostRequest(params ExecuteHttpPostRequestParams) ([]byte, error) {
	req, err := http.NewRequest("POST", params.URL, params.Payload)
	if err != nil {
		return nil, err
	}

	req.Header.Add("content-type", params.Headers.ContentType)
	if params.Headers.Authorization != "" {
		req.Header.Add("Authorization", params.Headers.Authorization)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

func executeOauthTokenRequest(params ExecuteHttpPostRequestParams) (*OauthTokenResponse, error) {
	body, err := executeHttpPostRequest(ExecuteHttpPostRequestParams{
		Payload: params.Payload,
		URL:     params.URL,
		Headers: RequestHeaders{
			ContentType: "application/x-www-form-urlencoded",
		},
	})

	var tokenResponse OauthTokenResponse
	err = json.Unmarshal([]byte(body), &tokenResponse)
	if err != nil {
		return nil, err
	}

	if tokenResponse.Error != "" {
		return nil, errors.New(tokenResponse.Error)
	}

	if params.Debug {
		err := prettyJSONLog("\n\noauth/token", body)
		if err != nil {
			return nil, err
		}
	}

	return &tokenResponse, nil
}

func getMGMTAPIToken(params MGMTAPIRequestParams) (*OauthTokenResponse, error) {
	payload := strings.NewReader(fmt.Sprintf("grant_type=client_credentials&client_id=%s&client_secret=%s&audience=%s", params.ClientID, params.ClientSecret, fmt.Sprintf("https://%s/api/v2/", params.Domain)))

	tokenResponse, err := executeOauthTokenRequest(ExecuteHttpPostRequestParams{
		Payload: payload,
		URL:     fmt.Sprintf("https://%s/oauth/token", params.Domain),
		Headers: RequestHeaders{
			ContentType: "application/x-www-form-urlencoded",
		},
		Debug: params.Debug,
	})
	if err != nil {
		return nil, err
	}

	return tokenResponse, nil
}

func createMyAccountRS(params MGMTAPIRequestParams) error {
	payload := strings.NewReader(fmt.Sprintf("{ \"identifier\": \"%s\", \"name\": \"Auth0 My Account API\", \"skip_consent_for_verifiable_first_party_clients\": false, \"token_dialect\": \"rfc9068_profile\" }", fmt.Sprintf("https://%s/me/", params.Domain)))

	body, err := executeHttpPostRequest(ExecuteHttpPostRequestParams{
		Payload: payload,
		URL:     fmt.Sprintf("https://%s/api/v2/resource-servers", params.Domain),
		Headers: RequestHeaders{
			ContentType:   "application/json",
			Authorization: fmt.Sprintf("Bearer %s", params.OauthTokenResponse.AccessToken),
		},
	})
	if err != nil {
		return err
	}

	if params.Debug {
		err := prettyJSONLog("\n\ncreateMyAccountRS", body)
		if err != nil {
			fmt.Print("\n\nprettyJSONLog - createMyAccountRS\n\n")
			return err
		}
	}

	var api2Response API2PostResponse
	err = json.Unmarshal([]byte(body), &api2Response)
	if err != nil {
		return err
	}
	if api2Response.Error != "" {
		return errors.New(fmt.Sprintf("\n\n/api/v2/resource-servers\n%s: %s", api2Response.Error, api2Response.Message))
	}

	return nil
}

func createMyAccountClientGrant(params MGMTAPIRequestParams) error {
	payload := strings.NewReader(fmt.Sprintf("{ \"client_id\": \"%s\", \"audience\": \"%s\", \"scope\": [\"create:authentication-methods\"] }", params.ClientID, fmt.Sprintf("https://%s/me/", params.Domain)))

	body, err := executeHttpPostRequest(ExecuteHttpPostRequestParams{
		Payload: payload,
		URL:     fmt.Sprintf("https://%s/api/v2/client-grants", params.Domain),
		Headers: RequestHeaders{
			ContentType:   "application/json",
			Authorization: fmt.Sprintf("Bearer %s", params.OauthTokenResponse.AccessToken),
		},
	})
	if err != nil {
		return err
	}

	if params.Debug {
		err := prettyJSONLog("\n\ncreateMyAccountClientGrant", body)
		if err != nil {
			fmt.Print("\n\nprettyJSONLog - createMyAccountClientGrant\n\n")
			return err
		}
	}

	var api2Response API2PostResponse
	err = json.Unmarshal([]byte(body), &api2Response)
	if err != nil {
		return err
	}
	if api2Response.Error != "" {
		return errors.New(fmt.Sprintf("\n\n/api/v2/client-grants\n%s: %s", api2Response.Error, api2Response.Message))
	}

	return nil
}

func getRSAccessToken(params MGMTAPIRequestParams) (*OauthTokenResponse, error) {
	payload := strings.NewReader(fmt.Sprintf("grant_type=password&username=%s&password=%s&scope=create:authentication-methods&audience=%s&client_id=%s&client_secret=%s", params.Username, params.Password, fmt.Sprintf("https://%s/me/", params.Domain), params.ClientID, params.ClientSecret))

	tokenResponse, err := executeOauthTokenRequest(ExecuteHttpPostRequestParams{
		Payload: payload,
		URL:     fmt.Sprintf("https://%s/oauth/token", params.Domain),
		Headers: RequestHeaders{
			ContentType: "application/x-www-form-urlencoded",
		},
		Debug: params.Debug,
	})
	if err != nil {
		return nil, err
	}

	return tokenResponse, nil
}

func checkConfig(config Config) error {
	if config.RS.Domain == nil {
		return errors.New("domain is required in your config json file")
	}
	if config.RS.ClientID == nil {
		return errors.New("client_id is required in your config json file")
	}
	if config.RS.ClientSecret == nil {
		return errors.New("client_secret is required in your config json file")
	}
	if config.RS.Username == nil {
		return errors.New("username is required in your config json file")
	}
	if config.RS.Password == nil {
		return errors.New("password is required in your config json file")
	}

	return nil
}

func handleRSToken(params HandleRSTokenParams) (*OauthTokenResponse, error) {
	err := checkConfig(params.Config)
	if err != nil {
		return nil, err
	}

	if params.Config.RS.SetupRS {
		mgmtAPIToken, err := getMGMTAPIToken(MGMTAPIRequestParams{
			ClientID:     *params.Config.RS.ClientID,
			ClientSecret: *params.Config.RS.ClientSecret,
			Domain:       *params.Config.RS.Domain,
			Debug:        params.Config.Debug,
		})
		if err != nil {
			return nil, err
		}

		err = createMyAccountRS(MGMTAPIRequestParams{
			OauthTokenResponse: *mgmtAPIToken,
			Domain:             *params.Config.RS.Domain,
			Debug:              params.Config.Debug,
		})
		if err != nil {
			return nil, err
		}

		err = createMyAccountClientGrant(MGMTAPIRequestParams{
			OauthTokenResponse: *mgmtAPIToken,
			Domain:             *params.Config.RS.Domain,
			ClientID:           *params.Config.RS.ClientID,
			Debug:              params.Config.Debug,
		})
		if err != nil {
			return nil, err
		}
	}

	token, err := getRSAccessToken(MGMTAPIRequestParams{
		Domain:       *params.Config.RS.Domain,
		ClientID:     *params.Config.RS.ClientID,
		ClientSecret: *params.Config.RS.ClientSecret,
		Username:     *params.Config.RS.Username,
		Password:     *params.Config.RS.Password,
		Debug:        params.Config.Debug,
	})
	if err != nil {
		return nil, err
	}

	return token, nil
}
