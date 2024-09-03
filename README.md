# OAuth1AuthorizationHeaderBuilder

[![Java CI with Maven](https://github.com/renefatuaki/oauth1-authorization-header-builder/actions/workflows/maven.yml/badge.svg)](https://github.com/renefatuaki/oauth1-authorization-header-builder/actions/workflows/maven.yml)
[![Maven Central Version](https://img.shields.io/maven-central/v/io.github.renefatuaki/oauth1-authorization-header-builder)](https://central.sonatype.com/artifact/io.github.renefatuaki/oauth1-authorization-header-builder)
[![javadoc](https://javadoc.io/badge2/io.github.renefatuaki/oauth1-authorization-header-builder/javadoc.svg)](https://javadoc.io/doc/io.github.renefatuaki/oauth1-authorization-header-builder)

A Java library for building OAuth1 authorization headers.

## Getting the latest release

Add the following dependency to your `pom.xml`:

```xml

<dependency>
	<groupId>io.github.renefatuaki</groupId>
	<artifactId>oauth1-authorization-header-builder</artifactId>
	<version>1.0.0</version>
</dependency>
```

Alternatively, you can pull it from the central Maven repositories:
[Maven Central Repository](https://central.sonatype.com/artifact/io.github.renefatuaki/oauth1-authorization-header-builder)

## Usage

### Example

Creating an OAuth1 Authorization Header for Twitter media upload endpoint:

```java
String authorization = new OAuth1AuthorizationHeaderBuilder()
		.setHttpMethod("POST")
		.setUrl("https://upload.twitter.com/1.1/media/upload.json")
		.setConsumerSecret(consumerSecret)
		.setTokenSecret(accessTokenSecret)
		.addParameter("oauth_consumer_key", consumerKey)
		.addParameter("oauth_token", accessToken)
		.addQueryParameter("additional_owners=" + id)
		.build();
```

## License

This code is licensed under the [Apache License v2](https://www.apache.org/licenses/LICENSE-2.0).