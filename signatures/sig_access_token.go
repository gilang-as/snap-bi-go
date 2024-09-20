package signatures

import (
	"crypto"
	"errors"
	"net/http"
	"strings"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type SignatureAccessTokenInput struct {
	Timestamp time.Time
}

type inputAccessToken struct {
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	Timestamp    time.Time `json:"timestamp"`
	PrivateKey   string    `json:"private_key"`
}

func (base *Base) SignatureAccessToken(alg string, input SignatureAccessTokenInput) (Signature, error) {
	var signature Signature
	var err error
	switch alg {
	case SignatureAlgAsymmetric:
		signature, err = sigAccessTokenAsymmetric(base.config, input)
	case SignatureAlgSymmetric:
		signature, err = sigAccessTokenSymmetric(base.config, input)
	default:
		panic("unknown signature algorithm: " + alg)
	}

	return signature, err
}

func (base *Base) VerifySignatureAccessToken(alg string, request *http.Request) error {
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
			validation.Field(&headers.Signature, validation.Required),
			validation.Field(&headers.PartnerID, validation.Required),
		)
	}

	if err := validate(headers); err != nil {
		return err
	}

	timestamp, _ := time.Parse(TimestampFormat, headers.TimeStamp)

	input := SignatureAccessTokenInput{
		Timestamp: timestamp,
	}

	var signature Signature
	var err error

	switch alg {
	case SignatureAlgAsymmetric:
		configData := &Config{
			ClientID:       headers.PartnerID,
			PrivateKeyPath: base.config.PrivateKeyPath,
			PublicKeyPath:  base.config.PublicKeyPath,
			PrivateKey:     base.config.PrivateKey,
			PublicKey:      base.config.PublicKey,
		}

		signature, err = sigAccessTokenAsymmetric(configData, input)
	case SignatureAlgSymmetric:
		configData := &Config{
			ClientID:     headers.PartnerID,
			ClientSecret: base.config.ClientSecret,
		}

		signature, err = sigAccessTokenSymmetric(configData, input)
	default:
		panic("unknown signature algorithm: " + alg)
	}

	if err != nil {
		return err
	}

	if isValid, err := signature.VerifySignature(headers.Signature); err != nil {
		return err
	} else if !isValid {
		return errors.New("invalid signature")
	}

	return nil
}

func sigAccessTokenAsymmetric(config *Config, input SignatureAccessTokenInput) (Signature, error) {
	validate := func(model inputAccessToken) error {
		return validation.ValidateStruct(&model,
			validation.Field(&model.ClientID, validation.Required),
			validation.Field(&model.PrivateKey, validation.Required),
			validation.Field(&model.Timestamp, validation.Required),
		)
	}

	clientID := config.ClientID
	privateKey, isPem, err := getPrivateKey(config)
	if err != nil {
		return nil, err
	}

	sigInput := inputAccessToken{
		ClientID:   clientID,
		Timestamp:  input.Timestamp,
		PrivateKey: privateKey,
	}

	if err := validate(sigInput); err != nil {
		return Signature{}, err
	}

	timestamp, err := changeTimeToIndo(input.Timestamp)
	if err != nil {
		return Signature{}, err
	}

	stringToSign := signatureFormatAsymmetric
	stringToSign = strings.Replace(stringToSign, formatClientID, clientID, -1)
	stringToSign = strings.Replace(stringToSign, formatTimestamp, timestamp, -1)

	sigData, err := getRsa(isPem, sigInput.PrivateKey, stringToSign)
	if err != nil {
		return Signature{}, err
	}

	signature := Signature(sigData)
	return signature, err
}

func sigAccessTokenSymmetric(config *Config, input SignatureAccessTokenInput) (Signature, error) {
	validate := func(model inputAccessToken) error {
		return validation.ValidateStruct(&model,
			validation.Field(&model.ClientID, validation.Required),
			validation.Field(&model.ClientSecret, validation.Required),
			validation.Field(&model.Timestamp, validation.Required),
		)
	}

	clientID := config.ClientID
	clientSecret := config.ClientSecret

	sigInput := inputAccessToken{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Timestamp:    input.Timestamp,
	}

	if err := validate(sigInput); err != nil {
		return Signature{}, err
	}

	timestamp := input.Timestamp.Format(TimestampFormat)

	stringToSign := signatureFormatSymmetric
	stringToSign = strings.Replace(stringToSign, formatClientID, clientID, -1)
	stringToSign = strings.Replace(stringToSign, formatTimestamp, timestamp, -1)

	sigData, err := getHmac(clientSecret, stringToSign, crypto.SHA512)
	if err != nil {
		return Signature{}, err
	}

	signature := Signature(sigData)
	return signature, err
}
