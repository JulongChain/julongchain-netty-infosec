package io.netty.handler.ssl;

/**
 * @purpose 国密证书和私钥对
 * @company Infosec Technology
 * @auther clf
 * @date 18-5-28
 */
public class GMCertEntry {
    private String cert;
    private String key;

    public GMCertEntry(String cert, String key) {
        this.cert = cert;
        this.key = key;
    }

    public String getCert() {
        return cert;
    }

    public void setCert(String cert) {
        this.cert = cert;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }
}
