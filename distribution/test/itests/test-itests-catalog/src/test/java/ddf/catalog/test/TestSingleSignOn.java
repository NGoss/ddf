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
package ddf.catalog.test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.isEmptyOrNullString;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.core.AllOf.allOf;
import static org.hamcrest.core.CombinableMatcher.both;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static com.jayway.restassured.RestAssured.get;
import static com.jayway.restassured.RestAssured.given;
import static com.jayway.restassured.authentication.CertificateAuthSettings.certAuthSettings;
import static ddf.common.test.WaitCondition.expect;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.URI;
import java.net.URLEncoder;
import java.util.Dictionary;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.ws.rs.core.UriBuilder;
import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import org.apache.commons.io.IOUtils;
import org.apache.cxf.jaxrs.impl.UriBuilderImpl;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.codice.ddf.security.common.jaxrs.RestSecurity;
import org.joda.time.DateTime;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.junit.PaxExam;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;
import org.osgi.service.cm.Configuration;
import org.xml.sax.SAXException;

import com.jayway.restassured.response.Response;

import ddf.common.test.BeforeExam;
import ddf.security.encryption.EncryptionService;
import ddf.security.samlp.SimpleSign;
import ddf.security.samlp.SystemCrypto;

@RunWith(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class TestSingleSignOn extends AbstractIntegrationTest {

    protected static final String KEY_STORE_PATH = System.getProperty("javax.net.ssl.keyStore");

    protected static final String PASSWORD = System.getProperty("javax.net.ssl.trustStorePassword");

    public static final String IDP_AUTH_TYPES = "/=SAML|ANON,/search=SAML|IDP|PKI,/solr=SAML|PKI|basic";

    private static final DynamicUrl SEARCH_URL = new DynamicUrl(DynamicUrl.SECURE_ROOT, HTTPS_PORT,
            "/search");

    private static final DynamicUrl WHO_AM_I_URL = new DynamicUrl(SERVICE_ROOT, "/whoami");

    protected final DynamicUrl AUTHENTICATION_REQUEST_ISSUER = new DynamicUrl(SERVICE_ROOT,
            "/saml/sso");

    @BeforeExam
    public void beforeTest() throws Exception {
        basePort = getBasePort();
        getAdminConfig().setLogLevels();
        getSecurityPolicy().configureWebContextPolicy(null, IDP_AUTH_TYPES, null, null);
        getServiceManager().waitForAllBundles();
        getServiceManager().waitForHttpEndpoint(SERVICE_ROOT + "/catalog/query");
        getServiceManager().waitForHttpEndpoint(WHO_AM_I_URL.getUrl());

        // Start the services needed for testing. We need to start the Search UI to test that it redirects properly
        getServiceManager().startFeature(true, "security-idp", "search-ui-app");

        // Get the metadata
        String serverMetadata = get(SERVICE_ROOT + "/idp/login/metadata").asString();
        String clientMetadata = get(SERVICE_ROOT + "/saml/sso/metadata").asString();

        // Ensure the metadata is valid according to the SAML Metadata schema
        Validator validator = getValidatorFor("saml-schema-metadata-2.0.xsd");
        validator.validate(new StreamSource(new StringReader(clientMetadata)));
        validator.validate(new StreamSource(new StringReader(serverMetadata)));

        setMetadata(clientMetadata, "metadata", "org.codice.ddf.security.idp.client.IdpMetadata",
                "saml-schema-metadata-2.0.xsd");
        setMetadata(serverMetadata, "spMetadata", "org.codice.ddf.security.idp.server.IdpEndpoint",
                "saml-schema-metadata-2.0.xsd");
    }

    private Validator getValidatorFor(String schemaFilename) throws SAXException {

        // Create a XML schema validator
        return SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI)
                .newSchema(getClass().getClassLoader().getResource(schemaFilename)).newValidator();
    }

    private void setMetadata(String metadata, String propertyName, String pid,
            String schemaFilename) throws SAXException, IOException {

        // Ensure the metadata is valid according to the SAML Metadata schema
        getValidatorFor(schemaFilename).validate(new StreamSource(new StringReader(metadata)));

        // To find the right inputs for the settings, go into the metatype.xml file.
        // The key is the "id" and the value type is determined by the cardinality as such:
        // Positive = array, negative = vector, 0 (none) = single variable
        Dictionary<String, Object> settings = new Hashtable<>();
        if (propertyName.equals("spMetadata")) {
            settings.put(propertyName, new String[] {metadata});
        } else {
            settings.put(propertyName, metadata);
        }

        // Update the client and server with the metadata
        final Configuration configuration = getAdminConfig().getConfiguration(pid, null);
        configuration.update(settings);

        //Wait for the updates to become effective
        expect("Configs to update").
                within(2, TimeUnit.MINUTES).
                until(() -> configuration.getProperties() != null &&
                            configuration.getProperties().get(propertyName) != null);
    }

    private String getRedirectUrl(Response response) {
        String fullUrl = null;

        // We can either get a legit redirect from the header, or we can have javascript redirect us.
        // Whenever javascript redirects us, we have to do ugly, fragile parsing of the HTML.
        if (response.headers().hasHeaderWithName("Location")) {
            fullUrl = response.header("Location");
        } else if (response.body().asString()
                .contains("<title>Redirect</title>")) { // Javascript redirect
            Pattern pattern = Pattern.compile("encoded *= *\"(.*)\"", Pattern.CASE_INSENSITIVE);
            Matcher matcher = pattern.matcher(response.body().asString());
            matcher.find();
            fullUrl = matcher.group(1);
        } else {
            fail("Unable to extract the redirect URL from the HTTP response. "
                    + "No redirect found in header and body does not match "
                    + "regular expression [encoded *= *\"(.*)\"]");
        }
        return fullUrl;
    }

    private String parseUrl(Response response) {
        return getRedirectUrl(response).split("[?]")[0];
    }

    private Map<String, String> parseParams(Response response) throws Exception {
        String url = getRedirectUrl(response);

        // RestAssured expects url query parameters to be in the form of a Dictionary.
        List<NameValuePair> paramList = URLEncodedUtils.parse(new URI(url), "UTF-8");
        HashMap<String, String> jsonParams = new HashMap<>();
        for (NameValuePair param : paramList) {
            jsonParams.put(param.getName(), param.getValue());
        }
        return jsonParams;
    }

    private Response getSearchResponse() {
        return given().redirects().follow(false).expect().statusCode(302).when().get(SEARCH_URL.getUrl());
    }

    private String getUserName(Map<String, String> cookies) {
        return given().cookies(cookies).when().get(WHO_AM_I_URL.getUrl()).body().asString();
    }

    private String getUserName() {
        return get(WHO_AM_I_URL.getUrl()).body().asString();
    }

    private void validateSamlResponse(Map<String, String> samlParams) throws Exception {
        String samlResponse = RestSecurity.inflateBase64(samlParams.get("SAMLResponse"));

        assertThat(samlParams.get("SigAlg"), not(isEmptyOrNullString()));
        assertThat(samlParams.get("Signature"), not(isEmptyOrNullString()));

        assertThat(samlResponse, allOf(containsString("urn:oasis:names:tc:SAML:2.0:status:Success"),
                containsString("ds:SignatureValue"), containsString("saml2:Assertion")));
        assertThat(samlParams.get("RelayState").length(),
                is(both(greaterThan(0)).and(lessThanOrEqualTo(80))));
    }

    @Test
    public void testBadUsernamePassword() throws Exception {
        Response searchResponse = getSearchResponse();

        // We're using an AJAX call, so anything other than 200 means not authenticated
        given().
                auth().preemptive().basic("definitely", "notright").
                param("AuthMethod", "up").
                params(parseParams(searchResponse)).
        expect().
                statusCode(not(200)).
        when().
                get(parseUrl(searchResponse) + "/sso");
    }

    @Test
    public void testPkiAuth() throws Exception {
        Response searchResponse = getSearchResponse();

        given().
                auth().
                certificate(KEY_STORE_PATH, PASSWORD,
                        certAuthSettings().sslSocketFactory(
                                SSLSocketFactory.getSystemSocketFactory())).
                param("AuthMethod", "pki").
                params(parseParams(searchResponse)).
        expect().
                statusCode(200).
        when().
                get(parseUrl(searchResponse) + "/sso");
    }

    @Test
    public void testGuestAuth() throws Exception {
        Response searchResponse = getSearchResponse();

        given().
                param("AuthMethod", "guest").
                params(parseParams(searchResponse)).
        expect().
                statusCode(200).
        when().
                get(parseUrl(searchResponse) + "/sso");
    }

    @Test
    public void testIdpAuth() throws Exception {

        // Negative test to make sure we aren't admin yet
        assertThat(getUserName(), not("admin"));

        // First time hitting search, expect to get redirected to the Identity Provider.
        Response searchResponse = getSearchResponse();

        // Pass our credentials to the IDP, it should redirect us to the Assertion Consumer Service.
        // The redirect is currently done via javascript and not an HTTP redirect.
        Response idpResponse =
                given().
                        auth().preemptive().basic("admin", "admin").
                        param("AuthMethod", "up").params(parseParams(searchResponse)).
                expect().
                        statusCode(200).
                        body(containsString("<title>Redirect</title>")).
                when().
                        get(parseUrl(searchResponse) + "/sso");

        // Make sure we pass a valid SAML assertion to the ACS
        validateSamlResponse(parseParams(idpResponse));

        // After passing the SAML Assertion to the ACS, we should be redirected back to Search.
        Response acsResponse =
                given().
                        params(parseParams(idpResponse)).
                        redirects().follow(false).
                expect().
                        statusCode(anyOf(is(302), is(303))).
                when().
                        get(parseUrl(idpResponse));

        // Access search again, but now as an authenticated user.
        given().
                cookies(acsResponse.getCookies()).
        expect().
                statusCode(200).
        when().
                get(parseUrl(acsResponse));

        // Make sure we are logged in as admin.
        assertThat(getUserName(acsResponse.getCookies()), is("admin"));
    }

    private String getMockSamlRequest() throws IOException, SAXException {

        String metadata = IOUtils
                .toString(getClass().getResourceAsStream("/confluence-sp-metadata.xml"));
        String md = String.format(metadata,AUTHENTICATION_REQUEST_ISSUER);
        setMetadata(md, "spMetadata", "org.codice.ddf.security.idp.server.IdpEndpoint",
                "saml-schema-metadata-2.0.xsd");
        InputStream istream = this.getClass()
                .getResourceAsStream("/confluence-sp-authentication-request.xml");
        assertThat("Could not read resource file for single sign on test", istream, notNullValue());
        String authRequestTemplate = IOUtils.toString(istream);
        String issueInstant = new DateTime().toString();
        String samlRequest = String
                .format(authRequestTemplate, AUTHENTICATION_REQUEST_ISSUER);

        return RestSecurity.deflateAndBase64Encode(samlRequest);
    }

    @Test
    public void testConfluenceSso() throws Exception {
        String idpUrl = new DynamicUrl(SERVICE_ROOT, "/idp/login/sso").getUrl();
        String mockSamlRequest = getMockSamlRequest();

        // Sign the query string -> SAMLRequest="blah"&RelayState="blah"&SigAlg="blah"
        String query = "SAMLRequest=" + URLEncoder.encode(mockSamlRequest, "UTF-8")
                     + "&RelayState=" + "test";
        String idpRequest = idpUrl + "?" + query;
        UriBuilder idpUri = new UriBuilderImpl(new URI(idpRequest));

        EncryptionService encryptionService = mock(EncryptionService.class);
        SystemCrypto systemCrypto = new SystemCrypto("encryption.properties",
                "signature.properties", encryptionService);
        SimpleSign simpleSign = new SimpleSign(systemCrypto);
        simpleSign.signUriString(query, idpUri);

        String url = idpUri.build().toString();

        given().
                auth().preemptive().basic("admin","admin").
                param("AuthMethod","up").
                param("SAMLRequest", mockSamlRequest).
                param("RelayState", "test").
                param("SigAlg","").
                param("Signature", "").
                redirects().follow(false).
        expect().
                statusCode(200).
        get(idpUrl).
                statusCode();
    }
}