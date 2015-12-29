/**
 * Copyright (c) Codice Foundation
 * <p>
 * This is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser
 * General Public License as published by the Free Software Foundation, either version 3 of the
 * License, or any later version.
 * <p>
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details. A copy of the GNU Lesser General Public License
 * is distributed along with this program and can be found at
 * <http://www.gnu.org/licenses/lgpl.html>.
 */
package org.codice.solr.factory;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import org.apache.solr.client.solrj.SolrServer;
import org.junit.Before;
import org.junit.Test;

public class TestSolrServerFactory {

    private static final String TEST_URL = "http://localhost/";

    private static final String TEST_CORENAME = "testCoreName";

    @Before
    public void setUp() {
        System.setProperty("https.cipherSuites",
                "TLS_DHE_RSA_WITH_AES_128_CBC_SHA,TLS_DHE_RSA_WITH_AES_128_CBC_SHA,TLS_DHE_DSS_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA");
    }

    @Test
    public void testSolrServerFactoryUrlAndCoreNameParams()
            throws ExecutionException, InterruptedException {
        Future<SolrServer> solrServerFuture = SolrServerFactory.getHttpSolrServer(TEST_URL,
                TEST_CORENAME);

        assertThat("solrServerFuture should not be null.", solrServerFuture, is(notNullValue()));
        assertThat("Should get back SolrServer from future.",
                solrServerFuture.get(),
                instanceOf(SolrServer.class));
    }

    @Test
    public void testSolrServerFactoryUrlParam() throws ExecutionException, InterruptedException {
        Future<SolrServer> solrServerFuture = SolrServerFactory.getHttpSolrServer(TEST_URL);

        assertThat("solrServerFuture should not be null.", solrServerFuture, is(notNullValue()));
        assertThat("Should get back SolrServer from future.",
                solrServerFuture.get(),
                instanceOf(SolrServer.class));
    }
}
