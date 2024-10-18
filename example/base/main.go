package main

import (
	"log"
	"time"

	"snap-bi/signatures"
)

func main() {
	sigBase := signatures.New()

	// if you didn't use environment variable, please uncomment this
	// configData := &signatures.Config{
	//   ClientID:       "your client id",
	//   ClientSecret:   "your client secret",
	//
	// // use either path if you use pem file
	// PrivateKeyPath: "/path/to/your/private_key.pem",
	//   PublicKeyPath:  "/path/to/your/public_key.pem",
	//
	// // or you encode base64 the contents of the pem file
	// PrivateKey:     "base64 encode contents of private_key.pem",
	//   PublicKey:      "base64 encode contents of public_key.pem",
	// }
	//
	// sigBase.SetConfig(configData)

	inputData := signatures.SignatureAccessTokenInput{
		Timestamp: time.Now(),
	}

	signature, err := sigBase.SignatureAccessToken(signatures.SignatureAlgSymmetric, inputData)
	if err != nil {
		panic(err.Error())
	}

	log.Printf(signature.StdEncoding())
}
