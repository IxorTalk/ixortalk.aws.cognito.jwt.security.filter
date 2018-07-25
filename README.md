## Introduction

This Spring Boot auto configuration module offers a security filter, capable of 

- Decoding an AWS Cognito JWT idToken
- Verifying the JWT token signature
- Verifying the JWT token issuer
- Creating a principal object using the username contained in the JWT token
- Convert the associated cognito groups into SimpleGrantedAuthorities

This modules aim to bridge the gap between Cognito identities and Spring Boot Security Principals.

## Usage

### Maven Dependency

The module is made available via Maven Central and is currently at version 0.0.6.
It can be added to your Maven based project like this :

```
<dependency>
    <groupId>com.ixortalk</groupId>
    <artifactId>ixortalk.aws.cognito.jwt.security.filter</artifactId>
    <version>0.0.7</version>
</dependency> 
```

or when using Gradle :

```
compile 'com.ixortalk:ixortalk.aws.cognito.jwt.security.filter:0.0.7'
```

### Security Configuration class

Create a security configuration, inject the AwsCognitoJwtAuthenticationFilter and add it to the filterchain.

```
@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter implements Ordered {

	private int order = 4;

	@Autowired
	private AwsCognitoJwtAuthenticationFilter awsCognitoJwtAuthenticationFilter;

	@Override
	public int getOrder() {
		return order;
	}

	public void setOrder(int order) {
		this.order = order;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.headers().cacheControl();
		http.csrf().disable()
				.authorizeRequests()
				.antMatchers("/health").permitAll()
				.antMatchers("/v2/**").permitAll()
				.antMatchers("/docs/**").permitAll()
				.antMatchers("/api/**").authenticated()
				.antMatchers("/**").permitAll() // needs to be the last matcher, otherwise all matchers following it would never be reached
				.anyRequest().authenticated()
				.and()
				.addFilterBefore(awsCognitoJwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
	}

}
```


This will add a security filter to your spring boot app that will look for a JWT idToken in the `Authorization` header of the request.

### Security Configuration Properties

In order to be able to verify and decode JWT Tokens, the module needs some Cognito configuration. This includes

- userPoolId
- identityPoolId
- region


Add the following configuration to your application to give the verifier sufficient information to decode the JWT token:

```
com:
  ixortalk:
    security:
        jwt:
          aws:
            userPoolId: "us-west-2_abcdefghi"
            identityPoolId: "us-west-2:xxxxxxxx-aaaa-bbbb-ccc-dddddddddddd"
            region: "us-west-2"
```

## HTTP call

To call a secure endpoint with a JWT token, add the authorization header with the Bearer type, followed by the actual token.

```
curl -v -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/secure | jq
```

## License

The MIT License (MIT)

Copyright (c) 2016-present IxorTalk CVBA

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
