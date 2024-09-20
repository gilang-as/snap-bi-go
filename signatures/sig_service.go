package signatures

import (
	"crypto"
	"strings"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type SignatureServiceInput struct {
	HttpMethod  string      `json:"http_method"`
	Url         string      `json:"url"`
	AccessToken string      `json:"access_token"`
	RequestBody interface{} `json:"request_body"`
	Timestamp   time.Time   `json:"timestamp"`
}

type inputSignatureService struct {
	HttpMethod   string      `json:"http_method"`
	Url          string      `json:"url"`
	UrlSignature string      `json:"url_signature"`
	AccessToken  string      `json:"access_token"`
	RequestBody  interface{} `json:"request_body"`
	Timestamp    string      `json:"timestamp"`

	ClientSecret string `json:"client_secret"`
	PrivateKey   string `json:"private_key"`
}

func (base *Base) SignatureService(alg string, input SignatureServiceInput) (Signature, error) {
	var signature Signature
	var err error
	switch alg {
	case SignatureAlgAsymmetric:
		signature, err = sigServiceAsymmetric(base.config, input)
	case SignatureAlgSymmetric:
		signature, err = sigServiceSymmetric(base.config, input)
	default:
		panic("unknown signature algorithm: " + alg)
	}

	return signature, err
}

func sigServiceAsymmetric(config *Config, input SignatureServiceInput) (Signature, error) {
	validate := func(model inputSignatureService) error {
		return validation.ValidateStruct(&model,
			validation.Field(&model.HttpMethod, validation.Required),
			validation.Field(&model.Url, validation.Required),
			validation.Field(&model.AccessToken, validation.Required),
			validation.Field(&model.Timestamp, validation.Required),
			validation.Field(&model.PrivateKey, validation.Required),
		)
	}

	privateKey, isPem, err := getPrivateKey(config)
	if err != nil {
		return nil, err
	}

	timestamp, err := changeTimeToIndo(input.Timestamp)
	if err != nil {
		return Signature{}, err
	}

	sigInput := inputSignatureService{
		HttpMethod:  input.HttpMethod,
		Url:         input.Url,
		AccessToken: input.AccessToken,
		RequestBody: input.RequestBody,
		Timestamp:   timestamp,
		PrivateKey:  privateKey,
	}

	if err = validate(sigInput); err != nil {
		return Signature{}, err
	}

	requestBody, err := generateRequestBody(input.RequestBody)
	if err != nil {
		return Signature{}, err
	}

	stringToSign := signatureServiceFormatAsymmetric
	stringToSign = strings.Replace(stringToSign, formatHttpMethod, input.HttpMethod, -1)
	stringToSign = strings.Replace(stringToSign, formatRelativeUrl, input.Url, -1)
	stringToSign = strings.Replace(stringToSign, formatTimestamp, timestamp, -1)

	if requestBody != "" {
		stringToSign = strings.Replace(stringToSign, formatRequestBody, requestBody, -1)
	} else {
		stringToSign = strings.Replace(stringToSign, ":"+formatRequestBody, requestBody, -1)
	}

	sigData, err := getRsa(isPem, sigInput.PrivateKey, stringToSign)
	if err != nil {
		return Signature{}, err
	}

	signature := Signature(sigData)
	return signature, err
}

func sigServiceSymmetric(config *Config, input SignatureServiceInput) (Signature, error) {
	validate := func(model inputSignatureService) error {
		return validation.ValidateStruct(&model,
			validation.Field(&model.HttpMethod, validation.Required),
			validation.Field(&model.Url, validation.Required),
			validation.Field(&model.AccessToken, validation.Required),
			validation.Field(&model.Timestamp, validation.Required),
			validation.Field(&model.ClientSecret, validation.Required),
		)
	}

	timestamp, err := changeTimeToIndo(input.Timestamp)
	if err != nil {
		return Signature{}, err
	}

	sigInput := inputSignatureService{
		HttpMethod:   input.HttpMethod,
		Url:          input.Url,
		AccessToken:  input.AccessToken,
		RequestBody:  input.RequestBody,
		Timestamp:    timestamp,
		ClientSecret: config.ClientSecret,
	}

	if err = validate(sigInput); err != nil {
		return Signature{}, err
	}

	requestBody, err := generateRequestBody(input.RequestBody)
	if err != nil {
		return Signature{}, nil
	}

	stringToSign := signatureServiceFormatSymmetric
	stringToSign = strings.Replace(stringToSign, formatHttpMethod, input.HttpMethod, -1)
	stringToSign = strings.Replace(stringToSign, formatRelativeUrl, input.Url, -1)
	stringToSign = strings.Replace(stringToSign, formatAccessToken, input.AccessToken, -1)
	stringToSign = strings.Replace(stringToSign, formatTimestamp, timestamp, -1)

	if requestBody != "" {
		stringToSign = strings.Replace(stringToSign, formatRequestBody, requestBody, -1)
	} else {
		stringToSign = strings.Replace(stringToSign, ":"+formatRequestBody, "", -1)
	}

	signature, err := getHmac(sigInput.ClientSecret, stringToSign, crypto.SHA512)
	return signature, err
}
