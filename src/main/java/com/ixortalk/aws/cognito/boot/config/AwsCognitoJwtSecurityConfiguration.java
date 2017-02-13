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
package com.ixortalk.aws.cognito.boot.config;

import com.ixortalk.aws.cognito.boot.JwtAuthentication;
import com.ixortalk.aws.cognito.boot.filter.AwsCognitoIdTokenProcessor;
import com.ixortalk.aws.cognito.boot.filter.AwsCognitoJwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class AwsCognitoJwtSecurityConfiguration extends WebSecurityConfigurerAdapter implements Ordered {

	private int order = 4;

	@Autowired
	private ApplicationContext context;

	@Autowired
	private AwsCognitoIdTokenProcessor awsCognitoIdTokenProcessor;

	@Autowired
	private AwsCognitoJtwConfiguration awsCognitoJtwConfiguration;

	@Autowired
	private JwtAuthenticationProvider jwtAuthenticationProvider;

	@Override
	public int getOrder() {
		return order;
	}

	public void setOrder(int order) {
		this.order = order;
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(jwtAuthenticationProvider);
	}
	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.headers().cacheControl();
		http.csrf().disable()
				.authorizeRequests()
				.antMatchers("/health").permitAll()
				.anyRequest().authenticated()
				.and()
				.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
	}

	private AwsCognitoJwtAuthenticationFilter jwtAuthenticationFilter() {

		return new AwsCognitoJwtAuthenticationFilter(awsCognitoIdTokenProcessor);
	}

}