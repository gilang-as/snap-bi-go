package security

import (
	"encoding/json"
	"errors"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-resty/resty/v2"
)

type B2BRequestBody struct {
	GrantType      string      `json:"grantType"`
	AdditionalInfo interface{} `json:"additionalInfo,omitempty"`
}

type B2BInput struct {
	Timestamp      string
	ClientID       string
	Signature      string
	AdditionalInfo interface{}
}

func (model B2BInput) Validate() error {
	return validation.ValidateStruct(&model,
		validation.Field(&model.Timestamp, validation.Required),
		validation.Field(&model.ClientID, validation.Required),
		validation.Field(&model.Signature, validation.Required),
	)
}

type B2BResponse struct {
	ResponseCode    string      `json:"responseCode"`
	ResponseMessage string      `json:"responseMessage"`
	AccessToken     string      `json:"accessToken"`
	TokenType       string      `json:"tokenType"`
	ExpiresIn       string      `json:"expiresIn"`
	AdditionalInfo  interface{} `json:"additionalInfo"`
}

func GetB2BAccessToken(input B2BInput, url string) (*B2BResponse, error) {
	if err := input.Validate(); err != nil {
		return nil, err
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
		SetBody(B2BRequestBody{
			GrantType:      "client_credentials",
			AdditionalInfo: input.AdditionalInfo,
		},
		).Post(url)
	if err != nil {
		return nil, err
	}

	var result B2BResponse
	err = json.Unmarshal(resp.Body(), &result)
	if err != nil {
		return nil, errors.New("failed to decode response body: " + err.Error())
	}

	return &result, nil
}
