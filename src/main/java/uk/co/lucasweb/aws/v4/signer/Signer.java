/*
  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
  the License. You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
  an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
  specific language governing permissions and limitations under the License.

  Copyright 2016 the original author or authors.
 */
package uk.co.lucasweb.aws.v4.signer;

import uk.co.lucasweb.aws.v4.signer.credentials.AwsCredentials;
import uk.co.lucasweb.aws.v4.signer.credentials.AwsCredentialsProviderChain;
import uk.co.lucasweb.aws.v4.signer.functional.Throwables;
import uk.co.lucasweb.aws.v4.signer.hash.Base16;
import uk.co.lucasweb.aws.v4.signer.hash.Sha256;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.util.*;

/**
 * @author Richard Lucas
 */
public class Signer {

    private static final String AUTH_TAG = "AWS4";
    private static final String ALGORITHM = AUTH_TAG + "-HMAC-SHA256";
    private static final Charset UTF_8 = Throwables.returnableInstance(() -> Charset.forName("UTF-8"), SigningException::new);
    private static final String X_AMZ_DATE = "X-Amz-Date";
    private static final String HMAC_SHA256 = "HmacSHA256";
    private static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";

    private final CanonicalRequest request;
    private final AwsCredentials awsCredentials;
    private final String date;
    private final CredentialScope scope;

    private Signer(CanonicalRequest request, AwsCredentials awsCredentials, String date, CredentialScope scope) {
        this.request = request;
        this.awsCredentials = awsCredentials;
        this.date = date;
        this.scope = scope;
    }

    String getCanonicalRequest() {
        return request.get();
    }

    String getStringToSign() {
        String hashedCanonicalRequest = Sha256.get(getCanonicalRequest(), UTF_8);
        return buildStringToSign(date, scope.get(), hashedCanonicalRequest);
    }

    /**
     * Returns the calculated signature represented as Authorization header value.<br>
     * e.g. AWS4-HMAC-SHA256 Credential="AccessKey"/20130524/us-east-1/s3/aws4_request,
     * SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature="Signature"
     * @return signature
     */
    public String getSignature() {
        String signature = buildSignature(awsCredentials.getSecretKey(), scope, getStringToSign());
        return buildAuthHeader(getCredential(awsCredentials.getAccessKey(), scope.get()), request.getHeaders().getNames(), signature);
    }

    /**
     * Returns the calculated signature represented as {@link Authorization} object. In this way the
     * calculated values can be retrieved individually.
     * @return signature as {@link Authorization}
     */
    public Authorization getSignatureValuesSeparately() {
        String signature = buildSignature(awsCredentials.getSecretKey(), scope, getStringToSign());
        String credential = getCredential(awsCredentials.getAccessKey(), scope.get());
        return new Authorization(ALGORITHM, credential, date, request.getHeaders().getNames(), signature);
    }

    public static Builder builder() {
        return new Builder();
    }

    private static String formatDateWithoutTimestamp(String date) {
        return date.substring(0, 8);
    }

    private static String buildStringToSign(String date, String credentialScope, String hashedCanonicalRequest) {
        return ALGORITHM + "\n" + date + "\n" + credentialScope + "\n" + hashedCanonicalRequest;
    }

    private static String buildAuthHeader(String credential, String signedHeaders, String signature) {
        return ALGORITHM + " " + "Credential=" + credential + ", " + "SignedHeaders=" + signedHeaders + ", " + "Signature=" + signature;
    }

    static String getCredential(String accessKey, String credentialScope) {
        return accessKey + "/" + credentialScope;
    }

    private static byte[] hmacSha256(byte[] key, String value) {
        try {
            String algorithm = HMAC_SHA256;
            Mac mac = Mac.getInstance(algorithm);
            SecretKeySpec signingKey = new SecretKeySpec(key, algorithm);
            mac.init(signingKey);
            return mac.doFinal(value.getBytes(UTF_8));
        } catch (Exception e) {
            throw new SigningException("Error signing request", e);
        }
    }

    private static String buildSignature(String secretKey, CredentialScope scope, String stringToSign) {
        byte[] kSecret = (AUTH_TAG + secretKey).getBytes(UTF_8);
        byte[] kDate = hmacSha256(kSecret, scope.getDateWithoutTimestamp());
        byte[] kRegion = hmacSha256(kDate, scope.getRegion());
        byte[] kService = hmacSha256(kRegion, scope.getService());
        byte[] kSigning = hmacSha256(kService, CredentialScope.TERMINATION_STRING);
        return Base16.encode(hmacSha256(kSigning, stringToSign)).toLowerCase();
    }

    public static class Builder {

        private static final String DEFAULT_REGION = "us-east-1";
        private static final int DEFAULT_EXPIRATION = 86400; // 24hrs
        private static final String S3 = "s3";
        private static final String GLACIER = "glacier";

        private AwsCredentials awsCredentials;
        private String region = DEFAULT_REGION;
        private int expiresIn = DEFAULT_EXPIRATION;
        private List<Header> headersList = new ArrayList<>();

        public Builder awsCredentials(AwsCredentials awsCredentials) {
            this.awsCredentials = awsCredentials;
            return this;
        }

        public Builder region(String region) {
            this.region = region;
            return this;
        }

        /**
         * Sets the expiration time of a pre-signed Url.
         * If not set, the default value (86400 seconds) will be used.
         * @param expiresInSeconds Expiration time in seconds.
         * @return {@link Builder}
         */
        public Builder expires(int expiresInSeconds) {
            this.expiresIn = expiresInSeconds;
            return this;
        }

        public Builder header(String name, String value) {
            headersList.add(new Header(name, value));
            return this;
        }

        public Builder header(Header header) {
            headersList.add(header);
            return this;
        }

        public Builder headers(Header... headers) {
            headersList.addAll(Arrays.asList(headers));
            return this;
        }

        /**
         * Builds a generic {@link Signer} for signing various kinds of requests.
         * @param request The http request.
         * @param service String representation of the service used. e.g. "s3"
         * @param contentSha256 A Sha256 encoded hash of the payload.
         * @return {@link Signer}
         */
        public Signer build(HttpRequest request, String service, String contentSha256) {
            CanonicalHeaders canonicalHeaders = getCanonicalHeaders();
            String date = canonicalHeaders.getFirstValue(X_AMZ_DATE)
                    .orElseThrow(() -> new SigningException("headers missing '" + X_AMZ_DATE + "' header"));
            String dateWithoutTimestamp = formatDateWithoutTimestamp(date);
            AwsCredentials awsCredentials = getAwsCredentials();
            CanonicalRequest canonicalRequest = new CanonicalRequest(service, request, canonicalHeaders, contentSha256);
            CredentialScope scope = new CredentialScope(dateWithoutTimestamp, service, region);
            return new Signer(canonicalRequest, awsCredentials, date, scope);
        }

        /**
         * Builds a generic {@link Signer} for signing S3 requests.
         * @param request The http request.
         * @param contentSha256 A Sha256 encoded hash of the payload.
         * @return {@link Signer}
         */
        public Signer buildS3(HttpRequest request, String contentSha256) {
            return build(request, S3, contentSha256);
        }

        /**
         * Builds a {@link Signer} for signing a pre-signed Url. Note: The essential query parameters like
         * X-Amz-Algorithm, X-Amz-Credential etc. should not be explicitly set in the Uri of the {@link HttpRequest},
         * they are added automatically! A pre-signed request will use an unsigned payload as content hash.
         * @param request The http request.
         * @param xAmzDate Date represented as ISO8201 string.
         * @return {@link Signer}
         */
        public Signer buildS3PreSignedUrl(HttpRequest request, String xAmzDate) {
            String service = S3;

            String dateWithoutTimestamp = formatDateWithoutTimestamp(xAmzDate);
            CredentialScope scope = new CredentialScope(dateWithoutTimestamp, service, region);
            AwsCredentials awsCredentials = getAwsCredentials();
            String credential = getCredential(awsCredentials.getAccessKey(), scope.get());

            CanonicalRequest canonicalRequest = new CanonicalRequest(service, request, getCanonicalHeaders(), UNSIGNED_PAYLOAD);
            canonicalRequest.addQueryParametersForPreSignedUrl(ALGORITHM, credential, xAmzDate, expiresIn);

            return new Signer(canonicalRequest, awsCredentials, xAmzDate, scope);
        }

        /**
         * Builds a generic {@link Signer} for signing Glacier requests.
         * @param request The http request.
         * @param contentSha256 A Sha256 encoded hash of the payload.
         * @return {@link Signer}
         */
        public Signer buildGlacier(HttpRequest request, String contentSha256) {
            return build(request, GLACIER, contentSha256);
        }

        private AwsCredentials getAwsCredentials() {
            return Optional.ofNullable(awsCredentials)
                    .orElseGet(() -> new AwsCredentialsProviderChain().getCredentials());
        }

        private CanonicalHeaders getCanonicalHeaders() {
            CanonicalHeaders.Builder builder = CanonicalHeaders.builder();
            headersList.forEach(h -> builder.add(h.getName(), h.getValue()));
            return builder.build();
        }

    }
}
