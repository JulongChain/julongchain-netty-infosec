/*
 * Copyright 2012 The Netty Project
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
package io.netty.example.securechat;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.example.telnet.TelnetServer;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextGMBuilder;
import io.netty.handler.ssl.util.SelfSignedCertificate;

/**
 * Simple SSL chat server modified from {@link TelnetServer}.
 */
public final class SecureChatServer {

    static final int PORT = Integer.parseInt(System.getProperty("port", "8992"));
    static final String TRUST_CERT = "MIICTTCCAfKgAwIBAgIKZCTXgL0MKPOtBzAMBggqgRzPVQGDdQUAMF0xCzAJBgNV\n" +
            "BAYTAkNOMTAwLgYDVQQKDCdDaGluYSBGaW5hbmNpYWwgQ2VydGlmaWNhdGlvbiBB\n" +
            "dXRob3JpdHkxHDAaBgNVBAMME0NGQ0EgVEVTVCBDUyBTTTIgQ0EwHhcNMTIxMjI1\n" +
            "MTIyNTA2WhcNMzIwNzIzMTIyNTA2WjBcMQswCQYDVQQGEwJDTjEwMC4GA1UECgwn\n" +
            "Q2hpbmEgRmluYW5jaWFsIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRswGQYDVQQD\n" +
            "DBJDRkNBIFRFU1QgU00yIE9DQTEwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAAQz\n" +
            "uFgJbedY55u6NToJElGWzPT+9UF1dxcopnerNO3fqRd4C1lDzz9LJZSfmMyNYaky\n" +
            "YC+6zh9G6/aPXW1Od/RFo4GYMIGVMB8GA1UdIwQYMBaAFLXYkG9c8Ngz0mO9frLD\n" +
            "jcZPEnphMAwGA1UdEwQFMAMBAf8wOAYDVR0fBDEwLzAtoCugKYYnaHR0cDovLzIx\n" +
            "MC43NC40Mi4zL3Rlc3RyY2EvU00yL2NybDEuY3JsMAsGA1UdDwQEAwIBBjAdBgNV\n" +
            "HQ4EFgQUa/4Y2o9COqa4bbMuiIM6NKLBMOEwDAYIKoEcz1UBg3UFAANHADBEAiAR\n" +
            "kDmkQ0Clio48994IUs63nA8k652O2C4+7EQs1SSbuAIgcwNUrHJyEYX8xT5BKl9T\n" +
            "lJOefzCNNJW5Z0f3Y/SjaG0=";
    static final String ENC_CERT = "MIICmjCCAj+gAwIBAgIFEAJlABAwDAYIKoEcz1UBg3UFADBcMQswCQYDVQQGEwJD\n" +
            "TjEwMC4GA1UECgwnQ2hpbmEgRmluYW5jaWFsIENlcnRpZmljYXRpb24gQXV0aG9y\n" +
            "aXR5MRswGQYDVQQDDBJDRkNBIFRFU1QgU00yIE9DQTEwHhcNMTUxMjE2MDY0MTA1\n" +
            "WhcNMTYxMjE2MDY0MTA1WjAxMQswCQYDVQQGEwJDTjENMAsGA1UECgwEQ0ZDQTET\n" +
            "MBEGA1UEAwwKMTI3LjAuMC4yNzBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABFMc\n" +
            "bMp7bz1xLUhw3Tv2PsMaEHnveSotGcrZrkJq8onmJ/J7DSDOavAIdfjxtPkl2FKr\n" +
            "Nhzbmut7TkvaJAXSQ7SjggEVMIIBETAfBgNVHSMEGDAWgBRr/hjaj0I6prhtsy6I\n" +
            "gzo0osEw4TBIBgNVHSAEQTA/MD0GCGCBHIbvKgEBMDEwLwYIKwYBBQUHAgEWI2h0\n" +
            "dHA6Ly93d3cuY2ZjYS5jb20uY24vdXMvdXMtMTQuaHRtMAwGA1UdEwEB/wQCMAAw\n" +
            "NwYDVR0fBDAwLjAsoCqgKIYmaHR0cDovL3VjcmwuY2ZjYS5jb20uY24vU00yL2Ny\n" +
            "bDkyOC5jcmwwDwYDVR0RBAgwBocEfwAAGzAOBgNVHQ8BAf8EBAMCAzgwHQYDVR0O\n" +
            "BBYEFPJi0ZRW9IhTkoQaHSPfm5pNLN6sMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggr\n" +
            "BgEFBQcDATAMBggqgRzPVQGDdQUAA0cAMEQCIAu+fG5rInhb0wYrjZAoiJBU+V0z\n" +
            "Ebqg/A0mGemDJjF1AiAhddXzojcsOaImdYEllWipKY9D2MkwvBsJDUlNLHSPkg==";
    static final String ENC_KEY = "MHcCAQEEILcC5tzydDR7Am5LCvc6WIwPvJWCU+RFQw062z0NuYJQoAoGCCqBHM9V\n" +
            "AYItoUQDQgAEUxxsyntvPXEtSHDdO/Y+wxoQee95Ki0ZytmuQmryieYn8nsNIM5q\n" +
            "8Ah1+PG0+SXYUqs2HNua63tOS9okBdJDtA==";
    static final String SIGN_CERT = "MIICnDCCAj+gAwIBAgIFEAJlAAkwDAYIKoEcz1UBg3UFADBcMQswCQYDVQQGEwJD\n" +
            "TjEwMC4GA1UECgwnQ2hpbmEgRmluYW5jaWFsIENlcnRpZmljYXRpb24gQXV0aG9y\n" +
            "aXR5MRswGQYDVQQDDBJDRkNBIFRFU1QgU00yIE9DQTEwHhcNMTUxMjE2MDY0MTA1\n" +
            "WhcNMTYxMjE2MDY0MTA1WjAxMQswCQYDVQQGEwJDTjENMAsGA1UECgwEQ0ZDQTET\n" +
            "MBEGA1UEAwwKMTI3LjAuMC4yNzBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABJFu\n" +
            "JgLqw/gJnOMAc2Vygwg51FqqThu/tQAy59aggsXcqyndnHQME6CclBwJ/jUdsXQV\n" +
            "z6ZDXeegOWvA7pqrgc6jggEVMIIBETAfBgNVHSMEGDAWgBRr/hjaj0I6prhtsy6I\n" +
            "gzo0osEw4TBIBgNVHSAEQTA/MD0GCGCBHIbvKgEBMDEwLwYIKwYBBQUHAgEWI2h0\n" +
            "dHA6Ly93d3cuY2ZjYS5jb20uY24vdXMvdXMtMTQuaHRtMAwGA1UdEwEB/wQCMAAw\n" +
            "NwYDVR0fBDAwLjAsoCqgKIYmaHR0cDovL3VjcmwuY2ZjYS5jb20uY24vU00yL2Ny\n" +
            "bDkyOC5jcmwwDwYDVR0RBAgwBocEfwAAGzAOBgNVHQ8BAf8EBAMCBsAwHQYDVR0O\n" +
            "BBYEFE2A8ydjS74G2SePqWdTTqn65x68MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggr\n" +
            "BgEFBQcDATAMBggqgRzPVQGDdQUAA0kAMEYCIQCVbIz9+jaGKnEvJ2pkQOyWmg9u\n" +
            "cchtuYHC/Mi4g7IhEgIhAPx0lKRHy3C7qt4siBg+f3DlX33n4yAIFSUaoRMepvM4";
    static final String SIGN_KEY = "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgJ9HQXXch/r9K08KO\n" +
            "IGmpylsjYIy+FsW8MeeIvs5Icu2hRANCAASRbiYC6sP4CZzjAHNlcoMIOdRaqk4b\n" +
            "v7UAMufWoILF3Ksp3Zx0DBOgnJQcCf41HbF0Fc+mQ13noDlrwO6aq4HO";


    public static void main(String[] args) throws Exception {
        SelfSignedCertificate ssc = new SelfSignedCertificate();
        /*SslContext sslCtx = SslContextBuilder.forServer(ssc.certificate(), ssc.privateKey())
            .build();*/
        SslContext sslCtx = SslContextGMBuilder.forServer(ENC_CERT, ENC_KEY, SIGN_CERT, SIGN_KEY, null)
                /* 默认协商出来的是ECDHE_SM4_SM3算法，所以必须是双向SSL，并且客户端和服务端必须要有加密证书和签名证书 */
                .clientAuth(ClientAuth.REQUIRE)
                .build();

        EventLoopGroup bossGroup = new NioEventLoopGroup(1);
        EventLoopGroup workerGroup = new NioEventLoopGroup();
        try {
            ServerBootstrap b = new ServerBootstrap();
            b.group(bossGroup, workerGroup)
             .channel(NioServerSocketChannel.class)
             .handler(new LoggingHandler(LogLevel.INFO))
             .childHandler(new SecureChatServerInitializer(sslCtx));

            b.bind(PORT).sync().channel().closeFuture().sync();
        } finally {
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
        }
    }
}
