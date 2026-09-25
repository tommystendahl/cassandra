/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.cassandra.net;

import java.net.InetSocketAddress;

import javax.net.ssl.SSLEngine;

import org.junit.BeforeClass;
import org.junit.Test;

import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.config.EncryptionOptions;
import org.apache.cassandra.security.ISslContextFactory;
import org.apache.cassandra.security.SSLFactory;
import org.apache.cassandra.transport.TlsTestUtils;

import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslHandler;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class SocketFactoryTest
{
    private static final InetSocketAddress PEER = new InetSocketAddress("127.0.0.1", 42123);

    @BeforeClass
    public static void setup()
    {
        DatabaseDescriptor.daemonInitialization();
    }

    private static SslContext serverSslContext() throws Exception
    {
        SSLFactory.clearSslContextCache();
        EncryptionOptions.ClientEncryptionOptions options = TlsTestUtils.getClientEncryptionOptions().applyConfig();
        return SSLFactory.getOrCreateSslContext(options,
                                                options.getClientAuth(),
                                                ISslContextFactory.SocketType.SERVER,
                                                "test");
    }

    @Test
    public void peerAddressAlwaysProvisionedWithoutEndpointVerification() throws Exception
    {
        EmbeddedChannel channel = new EmbeddedChannel();
        try
        {
            SslHandler handler = SocketFactory.newSslHandler(channel, serverSslContext(), PEER, false);
            SSLEngine engine = handler.engine();

            // Peer host/port provisioned on the engine as the numeric IP literal (no DNS lookup).
            assertEquals(PEER.getAddress().getHostAddress(), engine.getPeerHost());
            assertEquals(PEER.getPort(), engine.getPeerPort());

            // REQ-02: endpoint identification must NOT be enabled when verification was not requested.
            assertNull(engine.getSSLParameters().getEndpointIdentificationAlgorithm());
        }
        finally
        {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    public void endpointIdentificationEnabledWhenRequested() throws Exception
    {
        EmbeddedChannel channel = new EmbeddedChannel();
        try
        {
            SslHandler handler = SocketFactory.newSslHandler(channel, serverSslContext(), PEER, true);
            SSLEngine engine = handler.engine();

            assertEquals(PEER.getAddress().getHostAddress(), engine.getPeerHost());
            assertEquals("HTTPS", engine.getSSLParameters().getEndpointIdentificationAlgorithm());
        }
        finally
        {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    public void noPeerNoProvisioningNoEndpointVerification() throws Exception
    {
        EmbeddedChannel channel = new EmbeddedChannel();
        try
        {
            SslHandler handler = SocketFactory.newSslHandler(channel, serverSslContext(), null, false);
            SSLEngine engine = handler.engine();

            assertNull(engine.getPeerHost());
            assertNull(engine.getSSLParameters().getEndpointIdentificationAlgorithm());
        }
        finally
        {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    public void legacyOverloadCouplesPeerAndEndpointVerification() throws Exception
    {
        EmbeddedChannel channel = new EmbeddedChannel();
        try
        {
            SslHandler handler = SocketFactory.newSslHandler(channel, serverSslContext(), PEER);
            SSLEngine engine = handler.engine();

            assertNotNull(engine.getPeerHost());
            assertEquals("HTTPS", engine.getSSLParameters().getEndpointIdentificationAlgorithm());
        }
        finally
        {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    public void legacyOverloadNullPeerIsUnverified() throws Exception
    {
        EmbeddedChannel channel = new EmbeddedChannel();
        try
        {
            SslHandler handler = SocketFactory.newSslHandler(channel, serverSslContext(), null);
            SSLEngine engine = handler.engine();

            assertNull(engine.getPeerHost());
            assertNull(engine.getSSLParameters().getEndpointIdentificationAlgorithm());
        }
        finally
        {
            channel.finishAndReleaseAll();
        }
    }
}
