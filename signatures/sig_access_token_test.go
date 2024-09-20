package signatures

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var TestConfigSigAccessTokenData = &Config{
	ClientID:     "962489e9-de5d-4eb7-92a4-b07d44d64bf4",
	ClientSecret: "xS3vNQQgJRemFF0SZfXkZOq3r7kQ9n5YJgK4Wg0tVCQ=",
	PrivateKey: "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tDQoNCk1JSUV2d0lCQURBTkJna3Foa2l" +
		"HOXcwQkFRRUZBQVNDQktrd2dnU2xBZ0VBQW9JQkFRQ3RPeWt5dmJQS0RYYU0NCg0KNzkvTk1QTWRW" +
		"MTVWNEtvS3FPRldXK2JaeFVDSjVzdXU5WW9LZStnVXQ1V2tTa1BVR3V4RFIvdzcvTGszNGNlMw0KD" +
		"QpOQThMQzhlMExlM3ljVDkyUXVtOFVnelFrVW5Ra0FONXJpQ2w1WU1CeEhQZVlUeGx3akZrTkkzQX" +
		"JWdlFBeThODQoNCkFZdEpMSEpvblZDdXZoNHNRYmN0Zld5VlIvZms0ZVZLK3UwNmlHc1o1RFBCQ2N" +
		"rcUw5L0E4ZXordm1rVWVNTm4NCg0KZi9TL0RhR0t3ZDZGTU5FdEY3cjlIakxNNnp1SkJzcUU2NVdC" +
		"MDNPajZNMXZ3bm41MFRHai9wZlh4UHNmM3pkcg0KDQpuWnJ0dGc5Tlh3b2YxWHFUQTlnU3BXNHhQR" +
		"FZaTlVBTUxYSVNKN2VtZHp1b093M0JaMWplVHdmWFQrd0UvaDcvDQoNCkRFNUxGZDZ2QWdNQkFBRU" +
		"NnZ0VBR1hQcWh4SVRLMHBKeVBEVjFBaGFoYUo0c2VyalpuMlBNNzU5R2pJK3NWbS8NCg0KN21KcXp" +
		"lK01GMm5YWURSVDZGa0JyZXU5eHAxSXp2VXJBR0xJY3c4S3RoRlVONTNSZlViYzlsYWltMktTNkpv" +
		"Vg0KDQp2ZmlLYmlzSUoyZW92ckZRSVM0a283SGZ3aGUydUhHVXBZeVIzVWFINk9jZkc3aHVKb0tNQ" +
		"lBCbUsrajUwTW5zDQoNClJIWk9wY0QvYy9ockJjZnpDUHJZVUJWK2NMY0tQRFhtMlFHbXpXMGFOdD" +
		"ljUjNXc2UxcEREbEhFSWlxZC9QYjANCg0KdkFYeGZCNnJLQWlTUWNFYnp5L2tsWm1nQnFlajFucGh" +
		"GdW5kQ3Fyd2RmNlZLRmdLQ1Y2MTdVT1VWK3QrOFc2RQ0KDQpKdm80OVR5dEdyd1VMdWpzYVh5am9M" +
		"R1Vmc2FnUUU3bTcxNzMrRmNuZ1FLQmdRRDByc1FGeDVFYnc0U1J6dzVJDQoNCmJzRjlnZzJtSFNtU" +
		"Fg3OVBFYnBOOWhCQWZ6Tmo4SEk0QnFSRlR4SGs1S0c2dm5UcFEvTEFpaVpBYmRCMVdqdnQNCg0KdF" +
		"c1ZnVNbENtbFRQa056dGUvbkwrTDhkb3BPc201NE5oRmxtbnZxV2hCQzZibGhCVzFKZjhUaGFrYWR" +
		"oNmo5OA0KDQpBa0RsVTY5OEF4UUZBVlN6b3ZaeUZqbHhLUUtCZ1FDMVBscEV4N0hFQ2hneW5pMVI2" +
		"c1l3QzU5VjlWdHJHRlBhDQoNCkt5YTJEVXlUNmFDTFJjbDdhd29VOXQ3THRpQ0ZuNHdYbng2ZE1JZ" +
		"WxMRnEyR1dmOGZEa3M4V3g3S1QzN1FqVHINCg0KUWZEV0kzalBlS0JqN081cGk4WlN5bWIwSjJWdV" +
		"lVRHpEMVNWNzVXZXJLTHVwYjRvUXpMZEduaXpLb0FnOXFQRQ0KDQpsMFJpYlptVUZ3S0JnUUNUalV" +
		"TV2U2ZHRCN1hOUEFEUCswSmhqbWp1c0kxY2NZL3JmYlJNeVVNNXNidHEzQmYwDQoNCjQwUnlxMkVP" +
		"R0RYVGFJRVdIaXlvb1dhNTJiOG8xWlpvSGM0R21XZDg2NWFUYVRkaFd5N2pLd2tOTlBvNno4azcNC" +
		"g0KTzRHeUdkTGhxNWh1NUpZQ0s3RDhQSG9RVzkrRmMzNS9LTmk3c29DVGwwT2VWUlFnRS9qc0Nhen" +
		"dLUUtCZ1FDbQ0KDQpacXJsL3huOHpPL09lVjlPbUdpQmNBcElGMDVwa3hwWmNjakcySXI0T2tWRjJ" +
		"UclU3eitBWSsvRnhGOHpqM3BGDQoNCnJiZWp4Z3lqMzRjaExVNUZoNS9PM1pFbHVvWEhpOCtlTnhw" +
		"dzRIeG9yMjFDa1NPTEQrTnoyNVNPa1NVVkpJRkgNCg0KSjBvWHBySU56cDZBMFBjM2JBcms2UXJzS" +
		"kJjakxJN0xUYjVoU0JMNjNRS0JnUURVNnE3RGVVdnI5aEFSMTF4Sg0KDQpsUW1zemdFb3FnNjJRRG" +
		"NpS1FheSsrK0gwbUhsM3pudUg3TGRJMFVibFNGZjdrbzl5emJlblQ3UFh1d2ZPcEdBDQoNCktFNnY" +
		"1cEs1QzVDRXlVNlk4eXpXcWVlZzkrWUcxUVpRcE40MnhZOWFlNGZoeVM4NVhnU0Nnd3F0NW5ESWlQ" +
		"MGcNCg0KMlZoL1g4R0tRZ21aTmJsd3dMM05XRklGc3c9PQ0KDQotLS0tLUVORCBQUklWQVRFIEtFW" +
		"S0tLS0t",
}

var TimestampSigAccessTokenTest, _ = time.Parse(TimestampFormat, "2020-01-01T00:00:00+07:00")

var TestRequestBodySignatureAccessToken = `{
		"grantType":"client_credentials",
		"additionalInfo": {}
	}`

var SignatureAccessTokenAsymmetricResult = "X/lph2iR9UKSJ5tZw4/nLuS/tkbtYx+121kvkleRrJj1xFw/zVB" +
	"/shastWcS9tzu21fnzQYk4lRliqt5S9JRjJ5bZsnH/Jc+cq7q/GJtMwRxJXglX6vfZ/2Q4HXSOBWY9toXN35/T8lS7" +
	"1KS1mxcp5dByWs3RZjJdBReBRy18yvHskhlV5G/pwUnxpAkdSSIVgFpGbFBAhCmAX95+V1bDczlMUOw3z9PyQ97nOM" +
	"J/aSfSA7kcJpJrAFwGf/W+8TbjDTZ151smpwyctGRPPMQ6IN85N7q1IN/1EBE5TsATlh2ekSygv4PfKX8V1Z5aSz5m" +
	"2Cs35J9pCg4rFAskWiU4Q=="

var SignatureAccessTokenSymmetricResult = "kxZ0PJFmFVllsoVVZukP1lBtDajrkLnfcqNbf2JxvN8S7WDNq8kl" +
	"PMseQLXC7xILbY7JpdNvINp/I1Ar7VdYfg=="

func TestBase_SignatureAccessToken_Symmetric(t *testing.T) {
	sigBase := NewBase()
	sigBase.SetConfig(TestConfigSigAccessTokenData)

	inputData := SignatureAccessTokenInput{
		Timestamp: TimestampSigAccessTokenTest,
	}

	signature, err := sigBase.SignatureAccessToken(SignatureAlgSymmetric, inputData)
	if err != nil {
		t.Fatalf("Error in SignatureAccessToken Symmetric: %s", err.Error())
		return
	}

	if !assert.Equal(t, SignatureAccessTokenSymmetricResult,
		signature.StdEncoding()) {
		t.Fatalf("signature is not the same")
		return
	}
}

func TestBase_SignatureAccessToken_Asymmetric(t *testing.T) {
	sigBase := NewBase()
	sigBase.SetConfig(TestConfigSigAccessTokenData)

	inputData := SignatureAccessTokenInput{
		Timestamp: TimestampSigAccessTokenTest,
	}

	signature, err := sigBase.SignatureAccessToken(SignatureAlgAsymmetric, inputData)
	if err != nil {
		t.Fatalf("Error in SignatureAccessToken Asymmetric: %s", err.Error())
		return
	}

	if !assert.Equal(t, SignatureAccessTokenAsymmetricResult,
		signature.StdEncoding()) {
		t.Fatalf("Error in SignatureAccessToken Asymmetric: signature is not the same")
		return
	}
}

func TestBase_SignatureAccessToken_Symmetric_Validation(t *testing.T) {
	sigBase := NewBase()
	sigBase.SetConfig(TestConfigSigAccessTokenData)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/access-token/b2b", bytes.NewBuffer([]byte(TestRequestBodySignatureAccessToken)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-TIMESTAMP", TimestampSigAccessTokenTest.Format(TimestampFormat))
	req.Header.Set("X-CLIENT-KEY", TestConfigSigAccessTokenData.ClientID)
	req.Header.Set("X-SIGNATURE", SignatureAccessTokenSymmetricResult)

	err := sigBase.VerifySignatureAccessToken(SignatureAlgSymmetric, req)
	if err != nil {
		t.Fatalf("Error in SignatureAccessToken Symmetric: %s", err.Error())
		return
	}
}

func TestBase_SignatureAccessToken_Asymmetric_Validation(t *testing.T) {
	sigBase := NewBase()
	sigBase.SetConfig(TestConfigSigAccessTokenData)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/access-token/b2b", bytes.NewBuffer([]byte(TestRequestBodySignatureAccessToken)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-TIMESTAMP", TimestampSigAccessTokenTest.Format(TimestampFormat))
	req.Header.Set("X-CLIENT-KEY", TestConfigSigAccessTokenData.ClientID)
	req.Header.Set("X-SIGNATURE", SignatureAccessTokenAsymmetricResult)

	err := sigBase.VerifySignatureAccessToken(SignatureAlgAsymmetric, req)
	if err != nil {
		t.Fatalf("Error in SignatureAccessToken Symmetric: %s", err.Error())
		return
	}
}
