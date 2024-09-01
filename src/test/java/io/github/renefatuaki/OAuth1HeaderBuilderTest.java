package io.github.renefatuaki;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

class OAuth1HeaderBuilderTest {

	@Test
	void addParameter_withValidNameAndValue_addsParameterCorrectly() {
		OAuth1HeaderBuilder builder = new OAuth1HeaderBuilder();
		builder.addParameter("paramName", "paramValue");
		assertEquals("paramValue", builder.getParameters().get("paramName"));
	}

	@Test
	void addParameter_withNullName_throwsIllegalArgumentException() {
		OAuth1HeaderBuilder builder = new OAuth1HeaderBuilder();
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> builder.addParameter(null, "paramValue"));
		assertEquals("Parameter name cannot be null or empty", exception.getMessage());
	}

	@Test
	void addParameter_withEmptyName_throwsIllegalArgumentException() {
		OAuth1HeaderBuilder builder = new OAuth1HeaderBuilder();
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> builder.addParameter("", "paramValue"));
		assertEquals("Parameter name cannot be null or empty", exception.getMessage());
	}

	@Test
	void addParameter_withNullValue_throwsIllegalArgumentException() {
		OAuth1HeaderBuilder builder = new OAuth1HeaderBuilder();
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> builder.addParameter("paramName", null));
		assertEquals("Parameter value cannot be null", exception.getMessage());
	}

	@Test
	void addQueryParameter_withValidQueryParameter_addsParameterCorrectly() {
		OAuth1HeaderBuilder builder = new OAuth1HeaderBuilder();
		builder.addQueryParameter("param=value");
		assertEquals("value", builder.getQueryParametersMap().get("param"));
	}

	@Test
	void addQueryParameter_withQueryParameterWithoutValue_addsParameterWithEmptyValue() {
		OAuth1HeaderBuilder builder = new OAuth1HeaderBuilder();
		builder.addQueryParameter("param=");
		assertEquals("", builder.getQueryParametersMap().get("param"));
	}

	@Test
	void addQueryParameter_withNullQueryParameter_throwsIllegalArgumentException() {
		OAuth1HeaderBuilder builder = new OAuth1HeaderBuilder();
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> builder.addQueryParameter(null));
		assertEquals("Query parameter cannot be null or empty", exception.getMessage());
	}

	@Test
	void addQueryParameter_withEmptyQueryParameter_throwsIllegalArgumentException() {
		OAuth1HeaderBuilder builder = new OAuth1HeaderBuilder();
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> builder.addQueryParameter(""));
		assertEquals("Query parameter cannot be null or empty", exception.getMessage());
	}

	@Test
	void setConsumerSecret_withValidConsumerSecret_setsConsumerSecretCorrectly() {
		OAuth1HeaderBuilder builder = new OAuth1HeaderBuilder();
		builder.setConsumerSecret("validConsumerSecret");
		assertEquals("validConsumerSecret", builder.getConsumerSecret());
	}

	@Test
	void setConsumerSecret_withNullConsumerSecret_throwsIllegalArgumentException() {
		OAuth1HeaderBuilder builder = new OAuth1HeaderBuilder();
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> builder.setConsumerSecret(null));
		assertEquals("Consumer secret cannot be null", exception.getMessage());
	}

	@Test
	void setHttpMethod_withValidMethod_setsMethodCorrectly() {
		OAuth1HeaderBuilder builder = new OAuth1HeaderBuilder();
		builder.setHttpMethod("POST");
		assertEquals("POST", builder.getHttpMethod());
	}

	@Test
	void setHttpMethod_withNullMethod_throwsIllegalArgumentException() {
		OAuth1HeaderBuilder builder = new OAuth1HeaderBuilder();
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> builder.setHttpMethod(null));
		assertEquals("Method cannot be null or empty", exception.getMessage());
	}

	@Test
	void setHttpMethod_withEmptyMethod_throwsIllegalArgumentException() {
		OAuth1HeaderBuilder builder = new OAuth1HeaderBuilder();
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> builder.setHttpMethod(""));
		assertEquals("Method cannot be null or empty", exception.getMessage());
	}

	@Test
	void setTokenSecret_withValidTokenSecret_setsTokenSecretCorrectly() {
		OAuth1HeaderBuilder builder = new OAuth1HeaderBuilder();
		builder.setTokenSecret("validTokenSecret");
		assertEquals("validTokenSecret", builder.getTokenSecret());
	}

	@Test
	void setTokenSecret_withNullTokenSecret_throwsIllegalArgumentException() {
		OAuth1HeaderBuilder builder = new OAuth1HeaderBuilder();
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> builder.setTokenSecret(null));
		assertEquals("Token secret cannot be null", exception.getMessage());
	}

	@Test
	void setUrl_withValidUrlWithoutQuery_setsUrlCorrectly() {
		OAuth1HeaderBuilder builder = new OAuth1HeaderBuilder();
		builder.setUrl("http://example.com");
		assertEquals("http://example.com", builder.getUrl());
	}

	@Test
	void setUrl_withValidUrlWithQuery_setsUrlAndProcessesQueryParameters() {
		OAuth1HeaderBuilder builder = new OAuth1HeaderBuilder();
		builder.setUrl("http://example.com?param1=value1&param2=value2");
		assertEquals("http://example.com", builder.getUrl());
		assertEquals("value1", builder.getQueryParametersMap().get("param1"));
		assertEquals("value2", builder.getQueryParametersMap().get("param2"));
	}

	@Test
	void setUrl_withNullUrl_throwsIllegalArgumentException() {
		OAuth1HeaderBuilder builder = new OAuth1HeaderBuilder();
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> builder.setUrl(null));
		assertEquals("URL cannot be null or empty", exception.getMessage());
	}

	@ParameterizedTest
	@ValueSource(strings = {"", "   "})
	void setUrl_withInvalidUrl_throwsIllegalArgumentException(String url) {
		OAuth1HeaderBuilder builder = new OAuth1HeaderBuilder();
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> builder.setUrl(url));
		assertEquals("URL cannot be null or empty", exception.getMessage());
	}

	@Test
	void build_withValidParameters_returnsCorrectOAuthHeader() {
		OAuth1HeaderBuilder builder = new OAuth1HeaderBuilder();
		builder.setConsumerSecret("consumerSecret")
				.setTokenSecret("tokenSecret")
				.setHttpMethod("POST")
				.setUrl("http://example.com")
				.addParameter("oauth_consumer_key", "consumerKey")
				.addParameter("oauth_token", "token");

		String header = builder.build();

		assertTrue(header.startsWith("OAuth "));
		assertTrue(header.contains("oauth_consumer_key=\"consumerKey\""));
		assertTrue(header.contains("oauth_token=\"token\""));
		assertTrue(header.contains("oauth_signature="));
	}

	@Test
	void build_withMissingConsumerSecret_throwsIllegalArgumentException() {
		OAuth1HeaderBuilder builder = new OAuth1HeaderBuilder();
		builder.setTokenSecret("tokenSecret")
				.setHttpMethod("POST")
				.setUrl("http://example.com")
				.addParameter("oauth_consumer_key", "consumerKey")
				.addParameter("oauth_token", "token");

		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
		assertEquals("Consumer secret cannot be null", exception.getMessage());
	}

	@Test
	void build_withMissingHttpMethod_throwsIllegalArgumentException() {
		OAuth1HeaderBuilder builder = new OAuth1HeaderBuilder();
		builder.setConsumerSecret("consumerSecret")
				.setTokenSecret("tokenSecret")
				.setUrl("http://example.com")
				.addParameter("oauth_consumer_key", "consumerKey")
				.addParameter("oauth_token", "token");

		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
		assertEquals("Method cannot be null or empty", exception.getMessage());
	}

	@Test
	void build_withMissingUrl_throwsIllegalArgumentException() {
		OAuth1HeaderBuilder builder = new OAuth1HeaderBuilder();
		builder.setConsumerSecret("consumerSecret")
				.setTokenSecret("tokenSecret")
				.setHttpMethod("POST")
				.addParameter("oauth_consumer_key", "consumerKey")
				.addParameter("oauth_token", "token");

		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
		assertEquals("URL cannot be null or empty", exception.getMessage());
	}
}