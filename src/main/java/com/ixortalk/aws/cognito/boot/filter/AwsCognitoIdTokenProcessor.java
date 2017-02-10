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

import com.ixortalk.aws.cognito.boot.config.AwsCognitoCredentialsHolder;
import com.ixortalk.aws.cognito.boot.config.AwsCognitoJtwConfiguration;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

public class AwsCognitoIdTokenProcessor {

    protected final Log logger = LogFactory.getLog(getClass());

    public static final String EMPTY_PWD = "";

    @Autowired
    private AwsCognitoJtwConfiguration awsCognitoJtwConfiguration;

    @Autowired
    private ConfigurableJWTProcessor jwtProcessor;

    @Autowired
    private AwsCognitoCredentialsHolder awsCognitoCredentialsHolder;

    public Authentication getAuthentication(HttpServletRequest request) throws IOException {

        String idToken = request.getHeader(awsCognitoJtwConfiguration.getHttpHeader());
        if (idToken != null) {

            try {

                JWTClaimsSet claimsSet = jwtProcessor.process(idToken, null);

                if (!claimsSet.getIssuer().equals(awsCognitoJtwConfiguration.getCognitoIdentityPoolUrl())) {
                    throw new Exception(String.format("Issuer %s in JWT token doesn't match cognito idp %s",claimsSet.getIssuer(), awsCognitoJtwConfiguration.getCognitoIdentityPoolUrl()));
                }

                if (!claimsSet.getClaim("token_use").equals("id")) {
                    throw new Exception(String.format("JWT Token doesn't seem to be an ID Token"));
                }

                String username = claimsSet.getClaims().get(awsCognitoJtwConfiguration.getUserNameField()).toString();
                List<String> cognitoGroups = (List<String>) claimsSet.getClaims().get(awsCognitoJtwConfiguration.getGroupsField());

                if (username != null) {

                    List<GrantedAuthority> grantedAuthorities = convertList(cognitoGroups, group -> new SimpleGrantedAuthority("ROLE_" + group.toUpperCase()));
                    User user = new User(username, EMPTY_PWD, grantedAuthorities);

                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(user, EMPTY_PWD, grantedAuthorities);
                    usernamePasswordAuthenticationToken.setDetails(claimsSet.getClaims());

                    awsCognitoCredentialsHolder.setIdToken(idToken);
                    return usernamePasswordAuthenticationToken;
                }

            } catch (Exception ex) {
                logger.error("Error while processing JWT token",ex);
            }
        }
        return null;
    }

    public static <T, U> List<U> convertList(List<T> from, Function<T, U> func) {
        return from.stream().map(func).collect(Collectors.toList());
    }
}