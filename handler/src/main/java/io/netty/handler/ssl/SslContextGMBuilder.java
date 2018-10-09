/*
 * Copyright 2015 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package io.netty.handler.ssl;

import io.netty.buffer.ByteBuf;
import io.netty.util.internal.UnstableApi;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import static io.netty.util.internal.ObjectUtil.checkNotNull;

/**
 * Builder for configuring a new SslContext for creation.
 */
public final class SslContextGMBuilder {

    /**
     * Creates a builder for new client-side {@link SslContext}.
     */
    public static SslContextGMBuilder forClient() {
        return new SslContextGMBuilder(false);
    }

    /**
     * Creates a builder for new server-side {@link SslContext}.
     *
     * @param encCert encrypt certificate file in PEM format
     * @param encKey decrypt key file in PEM format
     * @param singCert sign certificate file in PEM format
     * @param signKey verify key file in PEM format
     * @param keyPassword the secret key of cert keys, or {@code null} if it's not
     *     password-protected
     * @see #keyManager(File, File, File, File, String)
     */
    public static SslContextGMBuilder forServer(File encCert, File encKey, File singCert, File signKey, String keyPassword) {
        return new SslContextGMBuilder(true).keyManager(encCert, encKey, singCert, signKey, keyPassword);
    }

    /**
     * Creates a builder for new server-side {@link SslContext}.
     *
     * @param encCert encrypt certificate String in PEM format
     * @param encKey decrypt key String in PEM format
     * @param singCert sign certificate String in PEM format
     * @param signKey verify key String in PEM format
     * @param keyPassword the secret key of cert keys, or {@code null} if it's not
     *     password-protected
     * @see #keyManager(String, String, String, String, String)
     */
    public static SslContextGMBuilder forServer(String encCert, String encKey, String singCert, String signKey, String keyPassword) {
        return new SslContextGMBuilder(true).keyManager(encCert, encKey, singCert, signKey, keyPassword);
    }

    /**
     * Creates a builder for new server-side {@link SslContext}.
     *
     * @param encCertEntry cert and key for ssl encryption and decryption
     * @param signCertEntry cert and key for ssl sign and verify
     * @param keyPassword the secret key of cert keys, or {@code null} if it's not
     *     password-protected
     * @see #keyManager(GMCertEntry, GMCertEntry, String)
     */
    public static SslContextGMBuilder forServer(GMCertEntry encCertEntry, GMCertEntry signCertEntry, String keyPassword) {
        return new SslContextGMBuilder(true).keyManager(encCertEntry, signCertEntry, keyPassword);
    }

    private final boolean forServer;
    private String[] trustCertCollection;
    private GMCertEntry encCertEntry;
    private GMCertEntry signCertEntry;
    private String keyPassword;
    private Iterable<String> ciphers;
    private CipherSuiteFilter cipherFilter = IdentityCipherSuiteFilter.INSTANCE;
    private ApplicationProtocolConfig apn;
    private long sessionCacheSize;
    private long sessionTimeout;
    private ClientAuth clientAuth = ClientAuth.NONE;
    private String[] protocols;
    private boolean startTls;
    private boolean enableOcsp;

    private SslContextGMBuilder(boolean forServer) {
        this.forServer = forServer;
    }

    /**
     * Trusted certificates for verifying the remote endpoint's certificate. The file should
     * contain an X.509 certificate collection in PEM format. {@code null} uses the system default.
     */
    public SslContextGMBuilder trustManager(File trustCertCollectionFile) {
        try {
            ByteBuf[] readCertificates = PemReader.readCertificates(trustCertCollectionFile);
            String[] trustCertCollection = new String[readCertificates.length];
            for (int i = 0; i < readCertificates.length; i++) {
                trustCertCollection[i] = readCertificates[i].toString();
            }
            return trustManager(trustCertCollection);
        } catch (Exception e) {
            throw new IllegalArgumentException("File does not contain valid certificates: "
                    + trustCertCollectionFile, e);
        }
    }

    /**
     * Trusted manager for verifying the remote endpoint's certificate. <b>can not</b> be {@code null}.
     */
    public SslContextGMBuilder trustManager(String... trustCertCollection) {
        if (null == trustCertCollection || trustCertCollection.length <= 0) {
            throw new IllegalArgumentException("trustCertCollection must be non-empty");
        }
        this.trustCertCollection = trustCertCollection;
        return this;
    }

    /**
     * Identifying certificate for this host. may
     * be {@code null} for client contexts, which disables mutual authentication.
     *
     * @param encCert cert in PEM format for ssl encryption
     * @param encKey key in PEM format for ssl decryption
     * @param signCert cert in PEM format for ssl signature
     * @param signKey key in PEM format for ssl verify
     * @param keyPassword the password of the {@code encKey} and {@code signKey}, or {@code null} if it's not
     *     password-protected
     */
    public SslContextGMBuilder keyManager(String encCert, String encKey, String signCert, String signKey,
                                          String keyPassword) {
        if (null == encCert || encCert.isEmpty()) {
            throw new IllegalArgumentException("encCertString must be non-empty");
        } else if (null == encKey || encKey.isEmpty()) {
            throw new IllegalArgumentException("encKeyString must be non-empty");
        } else if (null == signCert || signCert.isEmpty()) {
            throw new IllegalArgumentException("signCertString must be non-empty");
        } else if (null == signKey || signKey.isEmpty()) {
            throw new IllegalArgumentException("signCertString must be non-empty");
        }
        GMCertEntry encCertEntry = new GMCertEntry(encCert, encKey);
        GMCertEntry signCertEntry = new GMCertEntry(signCert, signKey);
        return keyManager(encCertEntry, signCertEntry, keyPassword);
    }

    /**
     * Identifying certificate for this host. may
     * be {@code null} for client contexts, which disables mutual authentication.
     *
     * @param encCert cert in PEM format for ssl encryption
     * @param encKey key in PEM format for ssl decryption
     * @param signCert cert in PEM format for ssl signature
     * @param signKey key in PEM format for ssl verify
     * @param keyPassword the password of the {@code encKey} and {@code signKey}, or {@code null} if it's not
     *     password-protected
     */
    public SslContextGMBuilder keyManager(File encCert, File encKey, File signCert, File signKey, String keyPassword) {
        if (forServer) {
            checkNotNull(signCert, "signCert required for servers");
            checkNotNull(signKey, "signKey required for servers");
            checkNotNull(encCert, "encCert required for servers");
            checkNotNull(encKey, "encKey required for servers");
        }
        try {
            String encCertString = PemReader.readContent(new FileInputStream(encCert));
            String encKeyString = PemReader.readContent(new FileInputStream(encKey));
            String signCertString = PemReader.readContent(new FileInputStream(signCert));
            String signKeyString = PemReader.readContent(new FileInputStream(signKey));
            return keyManager(encCertString, encKeyString, signCertString, signKeyString, keyPassword);
        } catch (IOException e) {
            throw new RuntimeException("exception occured while processing cert and key", e);
        }
    }

    /**
     * Identifying info for this host. may be {@code null} for
     * client contexts, which disables mutual authentication.
     * this only supported for  {@link SslProvider#OPENSSL}.
     * @param encCertEntry cert and key for ssl encryption and decryption
     * @param signCertEntry cert and key for ssl sign and verify
     * @param keyPassword the secret key of cert keys, or {@code null} if it's not
     *     password-protected
     */
    public SslContextGMBuilder keyManager(GMCertEntry encCertEntry, GMCertEntry signCertEntry, String keyPassword) {
        if (forServer) {
            checkNotNull(encCertEntry, "encCertEntry required for servers");
            checkNotNull(signCertEntry, "signCertEntry required for servers");
        }
        this.encCertEntry = encCertEntry;
        this.signCertEntry = signCertEntry;
        this.keyPassword = keyPassword;
        return this;
    }

    /**
     * The cipher suites to enable, in the order of preference. {@code null} to use default
     * cipher suites.
     */
    public SslContextGMBuilder ciphers(Iterable<String> ciphers) {
        return ciphers(ciphers, IdentityCipherSuiteFilter.INSTANCE);
    }

    /**
     * The cipher suites to enable, in the order of preference. {@code cipherFilter} will be
     * applied to the ciphers before use. If {@code ciphers} is {@code null}, then the default
     * cipher suites will be used.
     */
    public SslContextGMBuilder ciphers(Iterable<String> ciphers, CipherSuiteFilter cipherFilter) {
        checkNotNull(cipherFilter, "cipherFilter");
        this.ciphers = ciphers;
        this.cipherFilter = cipherFilter;
        return this;
    }

    /**
     * Application protocol negotiation configuration. {@code null} disables support.
     */
    public SslContextGMBuilder applicationProtocolConfig(ApplicationProtocolConfig apn) {
        this.apn = apn;
        return this;
    }

    /**
     * Set the size of the cache used for storing SSL session objects. {@code 0} to use the
     * default value.
     */
    public SslContextGMBuilder sessionCacheSize(long sessionCacheSize) {
        this.sessionCacheSize = sessionCacheSize;
        return this;
    }

    /**
     * Set the timeout for the cached SSL session objects, in seconds. {@code 0} to use the
     * default value.
     */
    public SslContextGMBuilder sessionTimeout(long sessionTimeout) {
        this.sessionTimeout = sessionTimeout;
        return this;
    }

    /**
     * Sets the client authentication mode.
     */
    public SslContextGMBuilder clientAuth(ClientAuth clientAuth) {
        this.clientAuth = checkNotNull(clientAuth, "clientAuth");
        return this;
    }

    /**
     * The TLS protocol versions to enable.
     * @param protocols The protocols to enable, or {@code null} to enable the default protocols.
     * @see SSLEngine#setEnabledCipherSuites(String[])
     */
    public SslContextGMBuilder protocols(String... protocols) {
        this.protocols = protocols == null ? null : protocols.clone();
        return this;
    }

    /**
     * {@code true} if the first write request shouldn't be encrypted.
     */
    public SslContextGMBuilder startTls(boolean startTls) {
        this.startTls = startTls;
        return this;
    }

    /**
     * Enables OCSP stapling. Please note that not all {@link SslProvider} implementations support OCSP
     * stapling and an exception will be thrown upon {@link #build()}.
     *
     * @see OpenSsl#isOcspSupported()
     */
    @UnstableApi
    public SslContextGMBuilder enableOcsp(boolean enableOcsp) {
        this.enableOcsp = enableOcsp;
        return this;
    }

    /**
     * Create new {@code SslContext} instance with configured settings.
     * the caller is responsible for releasing this object, or else native memory may leak.
     */
    public SslContext build() throws SSLException {
        if (forServer) {
            return SslContext.newServerContextInternal(trustCertCollection, encCertEntry, signCertEntry, keyPassword,
                ciphers, cipherFilter, apn, sessionCacheSize, sessionTimeout, clientAuth, protocols, startTls,
                enableOcsp);
        } else {
            return SslContext.newClientContextInternal(trustCertCollection, encCertEntry, signCertEntry, keyPassword,
                ciphers, cipherFilter, apn, protocols, sessionCacheSize, sessionTimeout, enableOcsp);
        }
    }
}
