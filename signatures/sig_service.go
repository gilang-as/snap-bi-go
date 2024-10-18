package signatures

import (
	"crypto"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"io"
	"net/http"
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

	SignatureHeader string `json:"signature_header"`
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
	PublicKey    string `json:"public_key"`
}

func (base *Snap) SignatureService(alg string, input SignatureServiceInput) (Signature, error) {
	var signature Signature
	var err error
	switch alg {
	case SignatureAlgAsymmetric:
		signature, _, err = sigServiceAsymmetric(base.config, input)
	case SignatureAlgSymmetric:
		signature, _, err = sigServiceSymmetric(base.config, input)
	default:
		panic("unknown signature algorithm: " + alg)
	}

	return signature, err
}

func (base *Snap) VerifySignatureService(alg string, request *http.Request) error {
	headers := getHeaders(request)
	var validate func(headers SignatureHeaders) error

	validate = func(headers SignatureHeaders) error {
		return validation.ValidateStruct(&headers,
			validation.Field(&headers.ContentType, validation.Required, validation.By(func(value interface{}) error {
				contentTypeHeader := value.(string)
				if strings.ToLower(contentTypeHeader) != "application/json" {
					return errors.New("Content-Type header is not application/json")
				}

				return nil
			})),
			validation.Field(&headers.TimeStamp, validation.Required, validation.By(func(value interface{}) error {
				timestampHeader := value.(string)
				_, err := time.Parse(TimestampFormat, timestampHeader)
				if err != nil {
					return err
				}

				return nil
			})),
			validation.Field(&headers.Authorization, validation.Required, validation.By(func(value interface{}) error {
				authorizationHeader := value.(string)
				if !strings.HasPrefix(authorizationHeader, "Bearer ") {
					return errors.New("authorization header is not valid, must be Bearer Token")
				}

				return nil
			})),
			validation.Field(&headers.ExternalID, validation.Required),
			validation.Field(&headers.Signature, validation.Required),
			validation.Field(&headers.PartnerID, validation.Required),
		)
	}

	if err := validate(headers); err != nil {
		return err
	}

	timestamp, _ := time.Parse(TimestampFormat, headers.TimeStamp)

	requestBody := new(strings.Builder)
	_, err := io.Copy(requestBody, request.Body)
	if err != nil {
		return err
	}

	var body interface{}
	if http.NoBody != request.Body {
		err = json.Unmarshal([]byte(requestBody.String()), &body)
		if err != nil {
			return err
		}
	} else {
		body = nil
	}

	token := headers.Authorization[7:]

	input := SignatureServiceInput{
		HttpMethod:      request.Method,
		Url:             request.URL.Path,
		AccessToken:     token,
		RequestBody:     body,
		Timestamp:       timestamp,
		SignatureHeader: headers.Signature,
	}

	var isValid bool

	switch alg {
	case SignatureAlgAsymmetric:
		configData := &Config{
			ClientID:       headers.PartnerID,
			PrivateKeyPath: base.config.PrivateKeyPath,
			PublicKeyPath:  base.config.PublicKeyPath,
			PrivateKey:     base.config.PrivateKey,
			PublicKey:      base.config.PublicKey,
		}

		_, isValid, err = sigServiceAsymmetric(configData, input)
	case SignatureAlgSymmetric:
		configData := &Config{
			ClientID:     headers.PartnerID,
			ClientSecret: base.config.ClientSecret,
		}

		_, isValid, err = sigServiceSymmetric(configData, input)
	default:
		panic("unknown signature algorithm: " + alg)
	}

	if err != nil {
		return err
	}

	if !isValid {
		return errors.New("invalid signature")
	}

	return nil
}

func sigServiceAsymmetric(config *Config, input SignatureServiceInput) (Signature, bool, error) {
	timestamp, err := changeTimeToIndo(input.Timestamp)
	if err != nil {
		return nil, false, err
	}

	sigInput := inputSignatureService{
		HttpMethod:  input.HttpMethod,
		Url:         input.Url,
		AccessToken: input.AccessToken,
		RequestBody: input.RequestBody,
		Timestamp:   timestamp,
	}

	validate := func(model inputSignatureService) error {
		return validation.ValidateStruct(&model,
			validation.Field(&model.HttpMethod, validation.Required),
			validation.Field(&model.Url, validation.Required),
			validation.Field(&model.AccessToken, validation.Required),
			validation.Field(&model.Timestamp, validation.Required),
		)
	}

	if err = validate(sigInput); err != nil {
		return nil, false, err
	}

	requestBody, err := generateRequestBody(input.RequestBody)
	if err != nil {
		return nil, false, err
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

	if input.SignatureHeader == "" {
		privateKey, isPem, err := getPrivateKey(config)
		if err != nil {
			return nil, false, err
		}

		inputRsa := RsaSignatureInput{
			IsPem:        isPem,
			PrivateKey:   privateKey,
			StringToSign: stringToSign,
			HashAlg:      crypto.SHA256,
		}

		sigData, _, err := getRsaSignature(inputRsa)
		if err != nil {
			return nil, false, err
		}

		signature := Signature(sigData)
		return signature, false, err
	} else {
		publicKey, isPem, err := getPublicKey(config)
		if err != nil {
			return nil, false, err
		}

		sigDecoded, _, err := getDecoding(input.SignatureHeader)
		if err != nil {
			return nil, false, err
		}

		inputRsa := RsaSignatureInput{
			IsPem:           isPem,
			StringToSign:    stringToSign,
			PublicKey:       publicKey,
			SignatureHeader: sigDecoded,
			HashAlg:         crypto.SHA256,
		}

		_, isValid, err := getRsaSignature(inputRsa)
		if err != nil {
			return nil, false, err
		}

		return nil, isValid, nil
	}
}

func sigServiceSymmetric(config *Config, input SignatureServiceInput) (Signature, bool, error) {
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
		return nil, false, err
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
		return nil, false, err
	}

	requestBody, err := generateRequestBody(input.RequestBody)
	if err != nil {
		return nil, false, err
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

	if input.SignatureHeader != "" {
		sigDecode, _, err := getDecoding(input.SignatureHeader)
		if err != nil {
			return nil, false, err
		}

		return signature, hmac.Equal(signature, sigDecode), nil
	} else {
		return signature, false, err
	}
}
