package security

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-resty/resty/v2"
)

type B2B2CRequestBody struct {
	GrantType      string      `json:"grantType"`
	AuthCode       string      `json:"authCode,omitempty"`
	RefreshToken   string      `json:"refreshToken,omitempty"`
	AdditionalInfo interface{} `json:"additionalInfo,omitempty"`
}

type B2B2CInput struct {
	Timestamp string
	ClientID  string
	Signature string

	GrantType    string // AUTHORIZATION_CODE | REFRESH_TOKEN
	AuthCode     string
	RefreshToken string

	AdditionalInfo interface{}
}

func (model B2B2CInput) Validate() error {
	return validation.ValidateStruct(&model,
		validation.Field(&model.Timestamp, validation.Required),
		validation.Field(&model.ClientID, validation.Required),
		validation.Field(&model.Signature, validation.Required),

		validation.Field(&model.GrantType, validation.Required, validation.By(func(value interface{}) error {
			grantType := strings.ToLower(value.(string))
			if grantType != "authorization_code" && grantType != "refresh_token" {
				return errors.New("grantType should be authorization_code or refresh_token")
			}

			return nil
		})),
	)
}

type B2B2CResponse struct {
	ResponseCode           string      `json:"responseCode"`
	ResponseMessage        string      `json:"responseMessage"`
	AccessToken            string      `json:"accessToken"`
	TokenType              string      `json:"tokenType"`
	AccessTokenExpiryTime  time.Time   `json:"accessTokenExpiryTime"`
	RefreshToken           string      `json:"refreshToken"`
	RefreshTokenExpiryTime time.Time   `json:"refreshTokenExpiryTime"`
	AdditionalInfo         interface{} `json:"additionalInfo"`
}

func GetB2B2CAccessToken(input B2B2CInput, url string) (*B2B2CResponse, error) {
	if err := input.Validate(); err != nil {
		return nil, err
	}

	if input.GrantType == "authorization_code" && input.AuthCode == "" {
		return nil, errors.New("authorization code is required")
	} else if input.GrantType == "refresh_token" && input.RefreshToken == "" {
		return nil, errors.New("refresh token is required")
	}

	client := resty.New()
	resp, err := client.R().
		SetHeaders(
			map[string]string{
				HeaderContentType: "application/json",
				HeaderTimestamp:   input.Timestamp,
				HeaderClientKey:   input.ClientID,
				HeaderSignature:   input.Signature,
			},
		).
		SetBody(B2B2CRequestBody{
			GrantType:      input.GrantType,
			AuthCode:       input.AuthCode,
			RefreshToken:   input.RefreshToken,
			AdditionalInfo: input.AdditionalInfo,
		},
		).Post(url)
	if err != nil {
		return nil, err
	}

	var result B2B2CResponse
	err = json.Unmarshal(resp.Body(), &result)
	if err != nil {
		return nil, errors.New("failed to decode response body: " + err.Error())
	}

	return &result, nil
}
