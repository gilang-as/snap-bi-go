package signatures

const TimestampFormat = "2006-01-02T15:04:05-07:00"
const TimestampTimezone = "Asia/Jakarta"

const SignatureAlgSymmetric = "signature_alg_symmetric"
const SignatureAlgAsymmetric = "signature_alg_asymmetric"

const formatClientID = "[CLIENT_ID]"
const formatTimestamp = "[TIMESTAMP]"
const formatHttpMethod = "[HTTP_METHOD]"
const formatRelativeUrl = "[RELATIVE_URL]"
const formatAccessToken = "[ACCESS_TOKEN]"
const formatRequestBody = "[REQUEST_BODY]"

const signatureFormatSymmetric = "[CLIENT_ID]|[TIMESTAMP]"
const signatureFormatAsymmetric = "[CLIENT_ID]|[TIMESTAMP]"

const signatureServiceFormatSymmetric = "[HTTP_METHOD]:[RELATIVE_URL]:[ACCESS_TOKEN]:[REQUEST_BODY]:[TIMESTAMP]"
const signatureServiceFormatAsymmetric = "[HTTP_METHOD]:[RELATIVE_URL]:[REQUEST_BODY]:[TIMESTAMP]"
