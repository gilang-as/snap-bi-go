package signatures

import (
	"crypto"
	"crypto/hmac"
	"errors"
	"net/http"
	"strings"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type SignatureAccessTokenInput struct {
	Timestamp       time.Time
	SignatureHeader string
}

type inputAccessToken struct {
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	Timestamp    time.Time `json:"timestamp"`
	PrivateKey   string    `json:"private_key"`
	PublicKey    string    `json:"public_key"`
}

func (base *Snap) SignatureAccessToken(alg string, input SignatureAccessTokenInput) (Signature, error) {
	var signature Signature
	var err error
	switch alg {
	case SignatureAlgAsymmetric:
		signature, _, err = sigAccessTokenAsymmetric(base.config, input)
	case SignatureAlgSymmetric:
		signature, _, err = sigAccessTokenSymmetric(base.config, input)
	default:
		panic("unknown signature algorithm: " + alg)
	}

	return signature, err
}

func (base *Snap) VerifySignatureAccessToken(alg string, request *http.Request) error {
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
			validation.Field(&headers.ClientKey, validation.Required),
		)
	}

	if err := validate(headers); err != nil {
		return err
	}

	timestamp, _ := time.Parse(TimestampFormat, headers.TimeStamp)

	input := SignatureAccessTokenInput{
		Timestamp:       timestamp,
		SignatureHeader: headers.Signature,
	}

	var isValid bool
	var err error

	switch alg {
	case SignatureAlgAsymmetric:
		configData := &Config{
			ClientID:       headers.ClientKey,
			PrivateKeyPath: base.config.PrivateKeyPath,
			PublicKeyPath:  base.config.PublicKeyPath,
			PrivateKey:     base.config.PrivateKey,
			PublicKey:      base.config.PublicKey,
		}

		_, isValid, err = sigAccessTokenAsymmetric(configData, input)
	case SignatureAlgSymmetric:
		configData := &Config{
			ClientID:     headers.ClientKey,
			ClientSecret: base.config.ClientSecret,
		}

		_, isValid, err = sigAccessTokenSymmetric(configData, input)
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

func sigAccessTokenAsymmetric(config *Config, input SignatureAccessTokenInput) (Signature, bool, error) {
	clientID := config.ClientID
	timestamp, err := changeTimeToIndo(input.Timestamp)
	if err != nil {
		return nil, false, err
	}

	sigInput := inputAccessToken{
		ClientID:  clientID,
		Timestamp: input.Timestamp,
	}

	validate := func(model inputAccessToken) error {
		return validation.ValidateStruct(&model,
			validation.Field(&model.ClientID, validation.Required),
			validation.Field(&model.Timestamp, validation.Required),
		)
	}

	if err = validate(sigInput); err != nil {
		return nil, false, err
	}

	stringToSign := signatureFormatAsymmetric
	stringToSign = strings.Replace(stringToSign, formatClientID, clientID, -1)
	stringToSign = strings.Replace(stringToSign, formatTimestamp, timestamp, -1)

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
		return signature, true, nil
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

func sigAccessTokenSymmetric(config *Config, input SignatureAccessTokenInput) (Signature, bool, error) {
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
		return nil, false, err
	}

	timestamp := input.Timestamp.Format(TimestampFormat)

	stringToSign := signatureFormatSymmetric
	stringToSign = strings.Replace(stringToSign, formatClientID, clientID, -1)
	stringToSign = strings.Replace(stringToSign, formatTimestamp, timestamp, -1)

	sigData, err := getHmac(clientSecret, stringToSign, crypto.SHA512)
	if err != nil {
		return nil, false, err
	}

	signature := Signature(sigData)

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
