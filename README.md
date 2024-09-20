# SNAP BI Golang

this repo is about wrapper for SNAP BI in golang language. you can access SNAP API on https://apidevportal.aspi-indonesia.or.id/api-services

# Features
- Signatures
  - Create
  - Verify
- Security (Keamanan)
  - B2B
  - B2B2C

# How to use

if you are using one type of provider, you can set environment variable so you don't need to set up configuration 
data. environment variable used are

```dotenv
BI_SNAP_CLIENT_ID
BI_SNAP_CLIENT_SECRET
BI_SNAP_PRIVATE_KEY_PATH
BI_SNAP_PUBLIC_KEY_PATH
BI_SNAP_PRIVATE_KEY
BI_SNAP_PUBLIC_KEY
```

## Signatures
> you can check how to create and verify signatures on signatures folder and check on test files, here are example 
> for symmetric case

### Create Signatures
```golang
package main

import (
  "log"
  "time"

  "snap-bi-go/signatures"
)

func main() {
  sigBase := signatures.NewBase()

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
```

### Verify Signatures

```golang
package main

import (
  "snap-bi-go/signatures"

  "github.com/gin-gonic/gin"
)

func SignatureValidationMiddleware() gin.HandlerFunc {
  return func(c *gin.Context) {
    sigBase := signatures.NewBase()
    err := sigBase.VerifySignatureAccessToken(signatures.SignatureAlgSymmetric, c.Request)
    if err != nil {
      c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid signature"})
	  return
    }
	
	c.Next()
  }
}

func main() {
  // Create a new Gin router
  r := gin.Default()

  // Apply the signature validation middleware globally
  r.Use(SignatureValidationMiddleware())

  // Define your routes
  r.POST("/auth/token", func(c *gin.Context) {
    // Assuming the signature is valid, you can proceed with your logic here
    c.JSON(200, gin.H{
      "message": "Token generated successfully",
    })
  })

  // Start the server
  r.Run(":8080") // Runs the server on port 8080
}
```