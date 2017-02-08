## Introduction

Spring Boot security filter, capable of 

- Decoding an AWS Cognito JWT idToken
- Verifying the signature
- Verifying the issuer
- Create a principal object using the username contained in the JWT token
- Convert the cognito groups into SimpleGrantedAuthorities

## Usage

Annotate your Spring Boot application with the `@AwsCognitoJwtVerifier` annotation.

```
package com.example;

import com.ixortalk.aws.cognito.boot.AwsCognitoJwtVerifier;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;

@SpringBootApplication(scanBasePackages = { "com.example","com.ixortalk" })
@AwsCognitoJwtVerifier
public class SampleApp {

	public static void main(String[] args) {
		SpringApplication.run(SampleApp.class, args);
	}

}
```

This will add a security filter to your spring boot app that will look for a base64 encoded JWT idToken in the `Authorization` header of the request.

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
