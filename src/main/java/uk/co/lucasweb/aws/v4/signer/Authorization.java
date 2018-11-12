package uk.co.lucasweb.aws.v4.signer;

/**
 * Created by sandro on 11/12/18
 */
public class Authorization {

    private String algorithm;
    private String credential;
    private String date;
    private String signedHeaders;
    private String signature;

    public Authorization(String algorithm, String credential, String date, String signedHeaders, String signature) {
        this.algorithm = algorithm;
        this.credential = credential;
        this.date = date;
        this.signedHeaders = signedHeaders;
        this.signature = signature;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getCredential() {
        return credential;
    }

    public String getDate() {
        return date;
    }

    public String getSignedHeaders() {
        return signedHeaders;
    }

    public String getSignature() {
        return signature;
    }
}
