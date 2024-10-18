package signatures

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"
)

type Snap struct {
	config *Config
}

type Config struct {
	ClientID     string
	ClientSecret string

	PrivateKeyPath string
	PublicKeyPath  string

	PrivateKey string
	PublicKey  string
}

var indoLoc *time.Location

func init() {
	var err error
	indoLoc, err = time.LoadLocation(TimestampTimezone)
	if err != nil {
		panic(err)
	}
}

func New() *Snap {
	return &Snap{
		config: &Config{
			ClientID:       os.Getenv("BI_SNAP_CLIENT_ID"),
			ClientSecret:   os.Getenv("BI_SNAP_CLIENT_SECRET"),
			PrivateKeyPath: os.Getenv("BI_SNAP_PRIVATE_KEY_PATH"),
			PublicKeyPath:  os.Getenv("BI_SNAP_PUBLIC_KEY_PATH"),
			PrivateKey:     os.Getenv("BI_SNAP_PRIVATE_KEY"),
			PublicKey:      os.Getenv("BI_SNAP_PUBLIC_KEY"),
		},
	}
}

func (base *Snap) SetConfig(config *Config) *Snap {
	if config == nil {
		panic("config is nil")
	}

	base.config = config
	return base
}

func (base *Snap) SetLocation(loc *time.Location) *Snap {
	if loc == nil {
		panic("location is nil")
	}

	indoLoc = loc
	return base
}

func getPrivateKey(config *Config) (string, bool, error) {
	var privateKey string
	var isPem bool
	if config.PrivateKeyPath != "" {
		privateKey = config.PrivateKeyPath
		isPem = true
	} else if config.PrivateKey != "" {
		privateKey = config.PrivateKey
		isPem = false
	} else {
		return "", isPem, fmt.Errorf("private key is empty")
	}

	return privateKey, isPem, nil
}

func getPublicKey(config *Config) (string, bool, error) {
	var publicKey string
	var isPem bool
	if config.PublicKeyPath != "" {
		publicKey = config.PublicKeyPath
		isPem = true
	} else if config.PublicKey != "" {
		publicKey = config.PublicKey
		isPem = false
	} else {
		return "", isPem, fmt.Errorf("public key is empty")
	}

	return publicKey, isPem, nil
}

func changeTimeToIndo(timeString time.Time) (string, error) {
	timestampIndo := timeString.In(indoLoc)
	return timestampIndo.Format(TimestampFormat), nil
}

func getHash(stringToHash string, hashType crypto.Hash) []byte {
	var mac hash.Hash
	switch hashType {
	case crypto.SHA256:
		mac = sha256.New()
	case crypto.SHA512:
		mac = sha512.New()
	default:
		mac = sha512.New()
	}

	mac.Write([]byte(stringToHash))
	resultHash := mac.Sum(nil)
	return resultHash
}

func getHmac(clientSecret string, stringToSign string, hashType crypto.Hash) ([]byte, error) {
	var mac hash.Hash
	switch hashType {
	case crypto.SHA256:
		mac = hmac.New(sha256.New, []byte(clientSecret))
	case crypto.SHA512:
		mac = hmac.New(sha512.New, []byte(clientSecret))
	default:
		mac = hmac.New(sha512.New, []byte(clientSecret))
	}

	_, err := mac.Write([]byte(stringToSign))
	if err != nil {
		return nil, err
	}

	return mac.Sum(nil), nil
}

type RsaSignatureInput struct {
	IsPem           bool
	PrivateKey      string
	StringToSign    string
	PublicKey       string
	SignatureHeader []byte
	HashAlg         crypto.Hash
}

func getRsaSignature(input RsaSignatureInput) ([]byte, bool, error) {
	var key string
	var isPublic bool
	if input.SignatureHeader != nil && input.PublicKey != "" {
		key = input.PublicKey
		isPublic = true
	} else {
		key = input.PrivateKey
		isPublic = false
	}

	var pemData []byte
	var err error
	if input.IsPem {
		pemData, err = os.ReadFile(key)
		if err != nil {
			return nil, false, err
		}
	} else {
		pemData, _, err = getDecoding(key)
		if err != nil {
			return nil, false, err
		}
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, false, errors.New("failed to parse PEM block, its empty")
	}

	hashString := getHash(input.StringToSign, input.HashAlg)

	if !isPublic {
		if block.Type != "PRIVATE KEY" && block.Type != "RSA PRIVATE KEY" {
			return nil, false, fmt.Errorf("failed to decode PEM block containing private key")
		}

		rsaPrivateKey, err := getRsaPrivateKey(block.Bytes)
		if err != nil {
			return nil, false, err
		}

		randomSeed := rand.New(rand.NewSource(time.Now().UnixNano()))
		cipherText, err := rsa.SignPKCS1v15(randomSeed, rsaPrivateKey, input.HashAlg, hashString)
		if err != nil {
			return nil, false, err
		}

		return cipherText, false, nil
	} else {
		if block.Type != "PUBLIC KEY" && block.Type != "RSA PUBLIC KEY" {
			return nil, false, fmt.Errorf("failed to decode PEM block containing private key")
		}

		rsaPublicKey, err := getRsaPublicKey(block.Bytes)
		if err != nil {
			return nil, false, err
		}

		err = rsa.VerifyPKCS1v15(rsaPublicKey, input.HashAlg, hashString, input.SignatureHeader)
		if err != nil {
			return nil, false, err
		}

		return nil, true, nil
	}
}

func generateRequestBody(requestBody interface{}) (string, error) {
	if requestBody == nil {
		return "", nil
	}

	bodyMarhsal, err := json.Marshal(requestBody)
	if err != nil {
		return "", err
	}

	bodyData := string(bodyMarhsal)
	resultHash := getHash(bodyData, crypto.SHA256)
	requestBodyResult := strings.ToLower(hex.EncodeToString(resultHash))
	return requestBodyResult, nil
}

func getDecoding(input string) ([]byte, string, error) {
	decodedString, errStdEncode := base64.StdEncoding.DecodeString(input)
	if errStdEncode == nil {
		return decodedString, base64StdEncoding, nil
	}

	decodedString, errRawStdEncode := base64.RawStdEncoding.DecodeString(input)
	if errRawStdEncode == nil {
		return decodedString, base64RawStdEncoding, nil
	}

	decodedString, errUrlEncode := base64.URLEncoding.DecodeString(input)
	if errUrlEncode == nil {
		return decodedString, base64UrlEncoding, nil
	}

	decodedString, errRawUrlEncode := base64.RawURLEncoding.DecodeString(input)
	if errRawUrlEncode == nil {
		return decodedString, base64RawUrlEncoding, nil
	}

	log.Printf("error decode StdEncoding : %s", errStdEncode)
	log.Printf("error decode RawStdEncoding : %s", errRawStdEncode)
	log.Printf("error decode UrlEncoding : %s", errUrlEncode)
	log.Printf("error decode RawUrlEncoding : %s", errRawUrlEncode)
	return nil, "", fmt.Errorf("failed to decode data")
}

func getRsaPrivateKey(privateKeyBlock []byte) (*rsa.PrivateKey, error) {
	parseKey, errPKCS8 := x509.ParsePKCS8PrivateKey(privateKeyBlock)
	if errPKCS8 == nil {
		return parseKey.(*rsa.PrivateKey), nil
	}

	parseKey, errPKCS1 := x509.ParsePKCS1PrivateKey(privateKeyBlock)
	if errPKCS1 == nil {
		return parseKey.(*rsa.PrivateKey), nil
	}

	log.Printf("error PKCS8 : %s", errPKCS8.Error())
	log.Printf("error PKCS1 : %s", errPKCS1.Error())
	return nil, fmt.Errorf("failed to parse private key, must be in PKCS8 or PKCS1")
}

func getRsaPublicKey(publicKeyBlock []byte) (*rsa.PublicKey, error) {
	parseKey, errPKCS1 := x509.ParsePKCS1PublicKey(publicKeyBlock)
	if errPKCS1 == nil {
		return parseKey, nil
	}

	parsedKey, errPKCS8 := x509.ParsePKIXPublicKey(publicKeyBlock)
	if errPKCS8 == nil {
		return parsedKey.(*rsa.PublicKey), nil
	}

	log.Printf("error PKCS8 : %s", errPKCS8.Error())
	log.Printf("error PKCS1 : %s", errPKCS1.Error())
	return nil, fmt.Errorf("failed to parse private key, must be in PKCS8 or PKCS1")
}

func getHeaders(request *http.Request) SignatureHeaders {
	headers := SignatureHeaders{
		ContentType:   request.Header.Get("Content-Type"),
		Authorization: request.Header.Get("Authorization"),
		TimeStamp:     request.Header.Get("X-TIMESTAMP"),
		Signature:     request.Header.Get("X-SIGNATURE"),
		PartnerID:     request.Header.Get("X-PARTNER-ID"),
		ExternalID:    request.Header.Get("X-EXTERNAL-ID"),
		ClientKey:     request.Header.Get("X-CLIENT-KEY"),
	}

	return headers
}
