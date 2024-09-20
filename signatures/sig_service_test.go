package signatures

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var TestConfigSigServiceData = &Config{
	ClientID:     "962489e9-de5d-4eb7-92a4-b07d44d64bf4",
	ClientSecret: "xS3vNQQgJRemFF0SZfXkZOq3r7kQ9n5YJgK4Wg0tVCQ=",
	PrivateKey:   "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tDQoNCk1JSUV2d0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktrd2dnU2xBZ0VBQW9JQkFRQ3RPeWt5dmJQS0RYYU0NCg0KNzkvTk1QTWRWMTVWNEtvS3FPRldXK2JaeFVDSjVzdXU5WW9LZStnVXQ1V2tTa1BVR3V4RFIvdzcvTGszNGNlMw0KDQpOQThMQzhlMExlM3ljVDkyUXVtOFVnelFrVW5Ra0FONXJpQ2w1WU1CeEhQZVlUeGx3akZrTkkzQXJWdlFBeThODQoNCkFZdEpMSEpvblZDdXZoNHNRYmN0Zld5VlIvZms0ZVZLK3UwNmlHc1o1RFBCQ2NrcUw5L0E4ZXordm1rVWVNTm4NCg0KZi9TL0RhR0t3ZDZGTU5FdEY3cjlIakxNNnp1SkJzcUU2NVdCMDNPajZNMXZ3bm41MFRHai9wZlh4UHNmM3pkcg0KDQpuWnJ0dGc5Tlh3b2YxWHFUQTlnU3BXNHhQRFZaTlVBTUxYSVNKN2VtZHp1b093M0JaMWplVHdmWFQrd0UvaDcvDQoNCkRFNUxGZDZ2QWdNQkFBRUNnZ0VBR1hQcWh4SVRLMHBKeVBEVjFBaGFoYUo0c2VyalpuMlBNNzU5R2pJK3NWbS8NCg0KN21KcXplK01GMm5YWURSVDZGa0JyZXU5eHAxSXp2VXJBR0xJY3c4S3RoRlVONTNSZlViYzlsYWltMktTNkpvVg0KDQp2ZmlLYmlzSUoyZW92ckZRSVM0a283SGZ3aGUydUhHVXBZeVIzVWFINk9jZkc3aHVKb0tNQlBCbUsrajUwTW5zDQoNClJIWk9wY0QvYy9ockJjZnpDUHJZVUJWK2NMY0tQRFhtMlFHbXpXMGFOdDljUjNXc2UxcEREbEhFSWlxZC9QYjANCg0KdkFYeGZCNnJLQWlTUWNFYnp5L2tsWm1nQnFlajFucGhGdW5kQ3Fyd2RmNlZLRmdLQ1Y2MTdVT1VWK3QrOFc2RQ0KDQpKdm80OVR5dEdyd1VMdWpzYVh5am9MR1Vmc2FnUUU3bTcxNzMrRmNuZ1FLQmdRRDByc1FGeDVFYnc0U1J6dzVJDQoNCmJzRjlnZzJtSFNtUFg3OVBFYnBOOWhCQWZ6Tmo4SEk0QnFSRlR4SGs1S0c2dm5UcFEvTEFpaVpBYmRCMVdqdnQNCg0KdFc1ZnVNbENtbFRQa056dGUvbkwrTDhkb3BPc201NE5oRmxtbnZxV2hCQzZibGhCVzFKZjhUaGFrYWRoNmo5OA0KDQpBa0RsVTY5OEF4UUZBVlN6b3ZaeUZqbHhLUUtCZ1FDMVBscEV4N0hFQ2hneW5pMVI2c1l3QzU5VjlWdHJHRlBhDQoNCkt5YTJEVXlUNmFDTFJjbDdhd29VOXQ3THRpQ0ZuNHdYbng2ZE1JZWxMRnEyR1dmOGZEa3M4V3g3S1QzN1FqVHINCg0KUWZEV0kzalBlS0JqN081cGk4WlN5bWIwSjJWdVlVRHpEMVNWNzVXZXJLTHVwYjRvUXpMZEduaXpLb0FnOXFQRQ0KDQpsMFJpYlptVUZ3S0JnUUNUalVTV2U2ZHRCN1hOUEFEUCswSmhqbWp1c0kxY2NZL3JmYlJNeVVNNXNidHEzQmYwDQoNCjQwUnlxMkVPR0RYVGFJRVdIaXlvb1dhNTJiOG8xWlpvSGM0R21XZDg2NWFUYVRkaFd5N2pLd2tOTlBvNno4azcNCg0KTzRHeUdkTGhxNWh1NUpZQ0s3RDhQSG9RVzkrRmMzNS9LTmk3c29DVGwwT2VWUlFnRS9qc0NhendLUUtCZ1FDbQ0KDQpacXJsL3huOHpPL09lVjlPbUdpQmNBcElGMDVwa3hwWmNjakcySXI0T2tWRjJUclU3eitBWSsvRnhGOHpqM3BGDQoNCnJiZWp4Z3lqMzRjaExVNUZoNS9PM1pFbHVvWEhpOCtlTnhwdzRIeG9yMjFDa1NPTEQrTnoyNVNPa1NVVkpJRkgNCg0KSjBvWHBySU56cDZBMFBjM2JBcms2UXJzSkJjakxJN0xUYjVoU0JMNjNRS0JnUURVNnE3RGVVdnI5aEFSMTF4Sg0KDQpsUW1zemdFb3FnNjJRRGNpS1FheSsrK0gwbUhsM3pudUg3TGRJMFVibFNGZjdrbzl5emJlblQ3UFh1d2ZPcEdBDQoNCktFNnY1cEs1QzVDRXlVNlk4eXpXcWVlZzkrWUcxUVpRcE40MnhZOWFlNGZoeVM4NVhnU0Nnd3F0NW5ESWlQMGcNCg0KMlZoL1g4R0tRZ21aTmJsd3dMM05XRklGc3c9PQ0KDQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0t",
}

var AccessTokenTest = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJhOGQ2YmVkNS05MzdkLTQzZTUtYTlkMi1hYWY0ODFlZjc2YTIiLCJjbGllbnRJZCI6IjZhZTk1N2M0LTI4NjMtNDcxMy1hY2NlLWJhMTJkZTYzNmNmYyIsIm5iZiI6MTYxMTM4NjM4NywiZXhwIjoxNjExMzg3Mjg3LCJpYXQiOjE2MTEzODYzODd9.nUillb6567_zkM6Ys35OOG-YWGoo7Ik1odPJn1tR-ao"
var TimestampSigServiceTest, _ = time.Parse(TimestampFormat, "2020-01-01T00:00:00+07:00")

var SignatureServiceAsymmetricResult = "AJvhevFApx+YtcXCZBnXFW9pSzzoqBzTJmLFtRzAklFEW1" +
	"/uBe5upsAd8Wvk3u8/lO6JslGUvzLeWoynERKPdZzLo7nAFDb5VSFaENaeYanZ2hgvCm9rOQJ1j4wEv8s" +
	"u2bHA97wMRt6jnKyhPcjd3v09pKwqca8bpJ5va4H2kIjtCZKDwc8SnTjJ7/hbSpJPCDIljRxCa+7UlSmZ" +
	"Zs1uCxMXC6u+x21QypctgenGApyXQyCIN1cTIlDNlcC0VtSWJ+rS5Ye7VUTcOYF5UjslcIPq6WNF446iz" +
	"TtPdxq3u6utM5ti8D4kjWBwsViSRslL0CCVI3zh0Bj2LUsytZlgUQ=="

var SignatureServiceSymmetricResult = "aqFyJg5631pb1qegHgkgFUNWdaD7fY6MCBbfYbIdcbyTO6Y" +
	"NEYT+wMpSmn1bnGiEjPBkSPGBPb42JK6gIalc+Q=="

func TestBase_SignatureService_Symmetric(t *testing.T) {
	sigBase := NewBase()
	sigBase.SetConfig(TestConfigSigServiceData)

	inputData := SignatureServiceInput{
		HttpMethod:  http.MethodPost,
		Url:         "/api/v1/balance-inquiry",
		AccessToken: AccessTokenTest,
		RequestBody: nil,
		Timestamp:   TimestampSigServiceTest,
	}

	signature, err := sigBase.SignatureService(SignatureAlgSymmetric, inputData)
	if err != nil {
		t.Fatalf("Error in SignatureAccessToken Symmetric: %s", err.Error())
		return
	}

	if !assert.Equal(t, SignatureServiceSymmetricResult,
		signature.StdEncoding()) {
		t.Fatalf("signature is not the same")
		return
	}
}

func TestBase_SignatureService_Asymmetric(t *testing.T) {
	sigBase := NewBase()
	sigBase.SetConfig(TestConfigSigServiceData)

	inputData := SignatureServiceInput{
		HttpMethod:  http.MethodPost,
		Url:         "/api/v1/balance-inquiry",
		AccessToken: AccessTokenTest,
		RequestBody: nil,
		Timestamp:   TimestampSigServiceTest,
	}

	signature, err := sigBase.SignatureService(SignatureAlgAsymmetric, inputData)
	if err != nil {
		t.Fatalf("Error in SignatureAccessToken Symmetric: %s", err.Error())
		return
	}

	if !assert.Equal(t, SignatureServiceAsymmetricResult,
		signature.StdEncoding()) {
		t.Fatalf("signature is not the same")
		return
	}
}

func TestBase_SignatureService_Symmetric_Validation(t *testing.T) {
	sigBase := NewBase()
	sigBase.SetConfig(TestConfigSigAccessTokenData)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/balance-inquiry", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-TIMESTAMP", TimestampSigAccessTokenTest.Format(TimestampFormat))
	req.Header.Set("Authorization", "Bearer "+AccessTokenTest)
	req.Header.Set("X-EXTERNAL-ID", time.Now().String())
	req.Header.Set("X-SIGNATURE", SignatureServiceSymmetricResult)
	req.Header.Set("X-PARTNER-ID", TestConfigSigAccessTokenData.ClientID)

	err := sigBase.VerifySignatureService(SignatureAlgSymmetric, req)
	if err != nil {
		t.Fatalf("Error in SignatureAccessToken Symmetric: %s", err.Error())
		return
	}
}

func TestBase_SignatureService_Asymmetric_Validation(t *testing.T) {
	sigBase := NewBase()
	sigBase.SetConfig(TestConfigSigAccessTokenData)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/balance-inquiry", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-TIMESTAMP", TimestampSigAccessTokenTest.Format(TimestampFormat))
	req.Header.Set("Authorization", "Bearer "+AccessTokenTest)
	req.Header.Set("X-EXTERNAL-ID", time.Now().String())
	req.Header.Set("X-SIGNATURE", SignatureServiceAsymmetricResult)
	req.Header.Set("X-PARTNER-ID", TestConfigSigAccessTokenData.ClientID)

	err := sigBase.VerifySignatureService(SignatureAlgAsymmetric, req)
	if err != nil {
		t.Fatalf("Error in SignatureAccessToken Symmetric: %s", err.Error())
		return
	}
}
