package io.github.renefatuaki;

import org.apache.commons.codec.EncoderException;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.commons.codec.net.URLCodec;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * A builder class for creating OAuth1 authorization headers.
 */
public class OAuth1AuthorizationHeaderBuilder {
	private String consumerSecret;
	private String httpMethod;
	private String signingKey;
	private String tokenSecret;
	private String url;
	private final Map<String, String> parameters = new LinkedHashMap<>();
	private final Map<String, String> queryParametersMap = new LinkedHashMap<>();
	private static final URLCodec CODEC = new URLCodec();

	/**
	 * Default constructor for OAuth1HeaderBuilder.
	 */
	public OAuth1AuthorizationHeaderBuilder() {
		// This constructor is intentionally empty.
	}

	/**
	 * Default constructor for OAuth1HeaderBuilder.
	 */
	public String getConsumerSecret() {
		return consumerSecret;
	}

	/**
	 * Gets the HTTP method.
	 *
	 * @return the HTTP method
	 */
	public String getHttpMethod() {
		return httpMethod;
	}

	/**
	 * Gets the signing key.
	 *
	 * @return the signing key
	 */
	public String getSigningKey() {
		return signingKey;
	}

	/**
	 * Gets the token secret.
	 *
	 * @return the token secret
	 */
	public String getTokenSecret() {
		return tokenSecret;
	}

	/**
	 * Gets the URL.
	 *
	 * @return the URL
	 */
	public String getUrl() {
		return url;
	}

	/**
	 * Gets the parameters.
	 *
	 * @return the parameters
	 */
	public Map<String, String> getParameters() {
		return parameters;
	}

	/**
	 * Gets the query parameters map.
	 *
	 * @return the query parameters map
	 */
	public Map<String, String> getQueryParametersMap() {
		return queryParametersMap;
	}

	/**
	 * Adds a parameter to the OAuth1 request.
	 *
	 * @param name  the name of the parameter
	 * @param value the value of the parameter
	 * @return the current instance for method chaining
	 * @throws IllegalArgumentException if the parameter name is null or empty, or if the parameter value is null
	 */
	public OAuth1AuthorizationHeaderBuilder addParameter(String name, String value) {
		if (name == null || name.isEmpty()) {
			throw new IllegalArgumentException("Parameter name cannot be null or empty");
		}
		if (value == null) {
			throw new IllegalArgumentException("Parameter value cannot be null");
		}
		parameters.put(name, value);
		return this;
	}

	/**
	 * Adds a query parameter to the URL query parameters map.
	 *
	 * @param queryParameter the query parameter in the format "key=value"
	 * @return the current instance for method chaining
	 * @throws IllegalArgumentException if the query parameter is null or empty
	 */
	public OAuth1AuthorizationHeaderBuilder addQueryParameter(String queryParameter) {
		if (queryParameter == null || queryParameter.isEmpty()) {
			throw new IllegalArgumentException("Query parameter cannot be null or empty");
		}

		String[] parameterParts = queryParameter.split("=", 2);
		String key = parameterParts[0];
		String value = parameterParts.length > 1 ? parameterParts[1] : "";

		this.queryParametersMap.put(key, value);

		return this;
	}

	/**
	 * Sets the consumer secret for OAuth1 authentication.
	 *
	 * @param consumerSecret the consumer secret to be set
	 * @return the current instance for method chaining
	 * @throws IllegalArgumentException if the consumer secret is null
	 */
	public OAuth1AuthorizationHeaderBuilder setConsumerSecret(String consumerSecret) {
		if (consumerSecret == null) {
			throw new IllegalArgumentException("Consumer secret cannot be null");
		}
		this.consumerSecret = consumerSecret;
		return this;
	}

	/**
	 * Sets the HTTP method for the OAuth1 request.
	 *
	 * @param method the HTTP method to be set (e.g., "GET", "POST")
	 * @return the current instance for method chaining
	 * @throws IllegalArgumentException if the method is null or empty
	 */
	public OAuth1AuthorizationHeaderBuilder setHttpMethod(String method) {
		if (method == null || method.isEmpty()) {
			throw new IllegalArgumentException("Method cannot be null or empty");
		}
		this.httpMethod = method;
		return this;
	}

	/**
	 * Sets the token secret for OAuth1 authentication.
	 *
	 * @param tokenSecret the token secret to be set
	 * @return the current instance for method chaining
	 * @throws IllegalArgumentException if the token secret is null
	 */
	public OAuth1AuthorizationHeaderBuilder setTokenSecret(String tokenSecret) {
		if (tokenSecret == null) {
			throw new IllegalArgumentException("Token secret cannot be null");
		}

		this.tokenSecret = tokenSecret;

		return this;
	}

	/**
	 * This method sets the base URL and processes any query parameters if present.
	 *
	 * @param url the URL to be set
	 * @return the current instance for method chaining
	 * @throws IllegalArgumentException if the URL is null or empty
	 */
	public OAuth1AuthorizationHeaderBuilder setUrl(String url) {
		if (url == null || url.isBlank()) {
			throw new IllegalArgumentException("URL cannot be null or empty");
		}

		int queryIndex = url.indexOf('?');

		if (queryIndex != -1) {
			this.url = url.substring(0, queryIndex);
			String query = url.substring(queryIndex + 1);
			handleQueryParam(query);
		} else {
			this.url = url;
		}
		return this;
	}

	/**
	 * Builds the OAuth1 authorization header string.
	 *
	 * @return the OAuth1 header string
	 */
	public String build() {
		if (consumerSecret == null) throw new IllegalArgumentException("Consumer secret cannot be null");
		if (httpMethod == null || httpMethod.isEmpty()) throw new IllegalArgumentException("Method cannot be null or empty");
		if (url == null || url.isEmpty()) throw new IllegalArgumentException("URL cannot be null or empty");

		parameters.putIfAbsent("oauth_timestamp", String.valueOf(Instant.now().getEpochSecond()));
		parameters.put("oauth_nonce", generateNonce());
		parameters.put("oauth_signature_method", "HMAC-SHA1");
		parameters.put("oauth_version", "1.0");
		parameters.putAll(queryParametersMap);

		String parameterString = parameters.entrySet().stream()
				.sorted(Map.Entry.comparingByKey())
				.map(param -> encodeUriComponent(param.getKey()) + "=" + encodeUriComponent(param.getValue()))
				.collect(Collectors.joining("&"));

		String signatureBaseString = httpMethod.toUpperCase() + "&" + encodeUriComponent(url) + "&" + encodeUriComponent(parameterString);

		if (signingKey == null) {
			signingKey = encodeUriComponent(consumerSecret) + "&" + (tokenSecret == null ? "" : encodeUriComponent(tokenSecret));
		}

		String signature = generateHmacSha1Signature(signingKey, signatureBaseString);
		parameters.put("oauth_signature", signature);

		return "OAuth " + parameters.entrySet().stream()
				.map(param -> encodeUriComponent(param.getKey()) + "=\"" + encodeUriComponent(param.getValue()) + "\"")
				.collect(Collectors.joining(", "));
	}

	/**
	 * Encodes the given URI component using URL encoding.
	 *
	 * @param uriComponent the URI component to be encoded
	 * @return the encoded URI component
	 */
	private String encodeUriComponent(String uriComponent) {
		try {
			return CODEC.encode(uriComponent);
		} catch (EncoderException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Generates an HMAC-SHA1 signature for the given message using the provided secret.
	 *
	 * @param secret  the secret key used for generating the HMAC-SHA1 signature
	 * @param message the message to be signed
	 * @return the Base64-encoded HMAC-SHA1 signature
	 */
	private String generateHmacSha1Signature(String secret, String message) {
		byte[] hmacSha1Bytes = new HmacUtils(HmacAlgorithms.HMAC_SHA_1, secret).hmac(message);
		return Base64.getEncoder().encodeToString(hmacSha1Bytes);
	}

	/**
	 * Generates a nonce (a unique, one-time-use value) for OAuth1 authentication.
	 * The nonce is a 15-digit random number, which is then hashed using MD5.
	 *
	 * @return a unique MD5 hash of a 15-digit random number
	 */
	private String generateNonce() {
		StringBuilder randomDigits = new StringBuilder(15);
		SecureRandom secureRandom = new SecureRandom();

		for (int i = 0; i < 15; i++) {
			randomDigits.append(secureRandom.nextInt(10));
		}

		return DigestUtils.md5Hex(randomDigits.toString());
	}

	/**
	 * Extracts and processes each query parameter.
	 *
	 * @param query the query parameters
	 */
	private void handleQueryParam(String query) {
		if (query == null || query.isBlank()) return;

		Arrays.stream(query.split("&"))
				.forEach(this::addQueryParameter);
	}
}
