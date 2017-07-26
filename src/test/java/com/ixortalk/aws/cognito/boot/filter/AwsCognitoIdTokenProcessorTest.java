/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2016-present IxorTalk CVBA
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package com.ixortalk.aws.cognito.boot.filter;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.ixortalk.aws.cognito.boot.config.JwtAutoConfiguration;
import com.ixortalk.aws.cognito.boot.config.JwtIdTokenCredentialsHolder;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.proc.BadJWTException;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;

import java.text.ParseException;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.ixortalk.aws.cognito.boot.filter.util.FileUtil.jsonFile;
import static org.apache.http.HttpStatus.SC_OK;
import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SpringRunner.class)
@WebAppConfiguration
@ContextConfiguration(classes = JwtAutoConfiguration.class,initializers = ConfigFileApplicationContextInitializer.class)
public class AwsCognitoIdTokenProcessorTest {

    private static final String KNOWN_KID = "1486832567";
    private static final String UNKNOWN_KID = "000000000";
    @Rule
    public WireMockRule wireMockRule = new WireMockRule(65432);

    protected static final String JWKS = jsonFile("jwk/keys.json");

    @Autowired
    private AwsCognitoIdTokenProcessor awsCognitoIdTokenProcessor;

    @Autowired
    private JwtIdTokenCredentialsHolder jwtIdTokenCredentialsHolder;

    private MockHttpServletRequest request = new MockHttpServletRequest();

    private MockHttpServletResponse response = new MockHttpServletResponse();

    private Authentication userAuthentication = new UsernamePasswordAuthenticationToken("marissa", "koala");

    @Before
    public void init() {
        setupJwkResource(JWKS);
    }

    @After
    public void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test(expected = ParseException.class)
    public void whenAuthorizationHeaderWithInvalidJWTValueProvidedParseExceptionOccurs() throws Exception {
        request.addHeader("Authorization", "Invalid JWT");
        awsCognitoIdTokenProcessor.getAuthentication(request);
    }

    @Test(expected = ParseException.class)
    public void whenAuthorizationHeaderWithEmptyJWTValueProvidedParseExceptionOccurs() throws Exception {
        request.addHeader("Authorization", "");
        awsCognitoIdTokenProcessor.getAuthentication(request);
    }

    @Test
    public void whenNoAuthorizationHeaderProvidedParseExceptionOccurs() throws Exception {
        assertThat(awsCognitoIdTokenProcessor.getAuthentication(request)).isNull();
    }

    @Test(expected = ParseException.class)
    public void whenUnsignedAuthorizationHeaderProvidedParseExceptionOccurs() throws Exception {
        request.addHeader("Authorization", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTMzNywidXNlcm5hbWUiOiJqb2huLmRvZSJ9");
        assertThat(awsCognitoIdTokenProcessor.getAuthentication(request)).isNull();
    }


    @Test(expected = BadJOSEException.class)
    public void whenSignedJWTWithoutMatchingKeyInAuthorizationHeaderProvidedParseExceptionOccurs() throws Exception {
        request.addHeader("Authorization", newJwtToken(UNKNOWN_KID,"role1").serialize());
        assertThat(awsCognitoIdTokenProcessor.getAuthentication(request)).isNull();
    }

    @Test
    public void whenSignedJWTWithMatchingKeyInAuthorizationHeaderProvidedAuthenticationIsReturned() throws Exception {
        request.addHeader("Authorization", newJwtToken(KNOWN_KID,"role1").serialize());
        Authentication authentication =  awsCognitoIdTokenProcessor.getAuthentication(request);
        assertThat(authentication.isAuthenticated()).isTrue();
    }

    @Test(expected = BadJWTException.class)
    public void whenExpiredJWTWithMatchingKeyInAuthorizationHeaderProvidedAuthenticationIsReturned() throws Exception {
        request.addHeader("Authorization", newJwtToken(KNOWN_KID,"expired").serialize());
        awsCognitoIdTokenProcessor.getAuthentication(request);
    }


    protected void setupJwkResource(String assetResponse) {
        wireMockRule.stubFor(get(urlEqualTo("/.well-known/jwks.json"))
                .willReturn(
                        aResponse()
                                .withBody(assetResponse)
                                .withStatus(SC_OK)
                ));
    }

    private JWSObject newJwtToken(String kid,String role) throws Exception {

        RSAKey rsaKey = RSAKey.parse(jsonFile("jwk/private_key.json"));
        JWSSigner signer = new RSASSASigner(rsaKey);

        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).build(),
                new Payload(jsonFile("jwk/payload-" + role + ".json")));

        jwsObject.sign(signer);

        return jwsObject;

    }

}
