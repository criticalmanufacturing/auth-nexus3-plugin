package com.criticalmanufacturing.auth.plugins.nexus3.api;

import com.criticalmanufacturing.auth.plugins.nexus3.AuthenticationException;
import com.criticalmanufacturing.auth.plugins.nexus3.Principal;
import com.criticalmanufacturing.auth.plugins.nexus3.SecurityPortalException;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.message.BasicNameValuePair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Singleton
@Named("SecurityPortalClient")
public class SecurityPortalClient {
    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityPortalClient.class);

    private HttpClient client;
    private SecurityPortalConfiguration configuration;
    private OidcMetadata oidcMetadata;

    private ObjectMapper mapper;
    private Cache<String, Principal> tokenToPrincipalCache;

    private Cache<String, Integer> tokenToErrorCodeCache;

    public SecurityPortalClient() {
        init();
    }

    public SecurityPortalClient(HttpClient client, SecurityPortalConfiguration configuration) {
        this.client = client;
        this.configuration = configuration;

        init();
    }

    @Inject
    public SecurityPortalClient(SecurityPortalConfiguration configuration) {
        this.configuration = configuration;
        init();
    }

    private void init() {
        LOGGER.info("Initializing Security Portal Client...");
        if (this.client == null) {

            RequestConfig config = RequestConfig.custom()
                    .setConnectTimeout(configuration.getRequestConnectTimeout())
                    .setConnectionRequestTimeout(configuration.getRequestConnectionRequestTimeout())
                    .setSocketTimeout(configuration.getRequestSocketTimeout())
                    .build();

            PoolingHttpClientConnectionManager manager = new PoolingHttpClientConnectionManager(60, TimeUnit.SECONDS);

            client = HttpClientBuilder
                    .create()
                    .setDefaultRequestConfig(config)
                    .setConnectionManager(manager)
                    .build();
        }

        mapper = new ObjectMapper();

        tokenToPrincipalCache = CacheBuilder.newBuilder()
                .expireAfterWrite(configuration.getPrincipalCacheTtl().toMillis(), TimeUnit.MILLISECONDS)
                .build();

        tokenToErrorCodeCache = CacheBuilder.newBuilder()
                .expireAfterWrite(configuration.getPrincipalCacheTtl().toMillis(), TimeUnit.MILLISECONDS)
                .build();
    }

    private <T> T serializeObject(HttpResponse response, Class<T> clazz) throws AuthenticationException {
        try
        {
            InputStreamReader reader = new InputStreamReader(response.getEntity().getContent());
            JavaType javaType = mapper.getTypeFactory()
                    .constructType(clazz);
            return mapper.readValue(reader, javaType);
        } catch (IOException e) {
            throw new AuthenticationException(e);
        }
    }

    private int validateStatusCode(HttpResponse response, String operation, String token) throws SecurityPortalException {
        int statusCode = response.getStatusLine().getStatusCode();

        SecurityPortalException exp;
        if (statusCode != 200) {
            switch (statusCode) {
                case 401:
                case 403:
                    exp = new AuthenticationException("Error while " + operation, statusCode, token);
                    LOGGER.warn("Error while " + operation, exp);

                    throw exp;
                default:
                    exp = new SecurityPortalException("Failed while " + operation, statusCode);
                    LOGGER.error("Failed while " + operation, exp);
                    throw exp;
            }
        }

        return statusCode;
    }


    private OidcMetadata getOidcInformation() throws SecurityPortalException {
        LOGGER.info("Fetching OIDC information...");
        HttpGet oidcRequest = new HttpGet(this.configuration.getMetadataUrl());

        try {
            HttpResponse response = this.client.execute(oidcRequest);

            validateStatusCode(response, "Fetching OIDC metadata", null);

            return serializeObject(response, OidcMetadata.class);

        } catch (IOException e) {
            throw new AuthenticationException(e);
        } finally {
            oidcRequest.releaseConnection();
        }

    }

    private SecurityPortalUser getUserInformation(SecurityPortalTokenResponse tokens) throws  SecurityPortalException {

        LOGGER.info("Fetching User Information");

        String token = tokens.getAccessToken();

        HttpGet httpGetUser = new HttpGet(this.oidcMetadata.getUserinfoEndpoint());
        httpGetUser.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);

        try {
            HttpResponse response = this.client.execute(httpGetUser);

            validateStatusCode(response,"Retrieving User Information", token);

            return serializeObject(response, SecurityPortalUser.class);

        } catch (IOException e) {
            throw new SecurityPortalException(e);
        } finally {
            httpGetUser.releaseConnection();
        }
    }

    private SecurityPortalRolesResponse getUserRoles(SecurityPortalTokenResponse tokens) throws SecurityPortalException {
        LOGGER.info("Fetching User Roles");

        String token = tokens.getAccessToken();

        HttpGet httpGetUserRoles = new HttpGet(this.oidcMetadata.getUserinfoEndpoint() + "/roles");
        httpGetUserRoles.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);

        try {
            HttpResponse response = this.client.execute(httpGetUserRoles);

            validateStatusCode(response,"Retrieving User Roles", token);

            return serializeObject(response, SecurityPortalRolesResponse.class);

        } catch (IOException e) {
            throw new SecurityPortalException(e);
        } finally {
            httpGetUserRoles.releaseConnection();
        }
    }

    private SecurityPortalTokenResponse exchangeToken(String clientId, String token) throws SecurityPortalException {
        LOGGER.info("Exchanging tokens...");

        HttpPost httpPost = new HttpPost(this.oidcMetadata.getTokenEndpoint());

        // Request parameters
        List<NameValuePair> params = new ArrayList<NameValuePair>(3);
        params.add(new BasicNameValuePair("client_id", clientId));
        params.add(new BasicNameValuePair("grant_type", "refresh_token"));
        params.add(new BasicNameValuePair("refresh_token", token));

        try {
            httpPost.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));
            HttpResponse response = this.client.execute(httpPost);

            validateStatusCode(response,"Exchanging Tokens", token);

            LOGGER.info("Tokens exchanged. Handling response...");
            return serializeObject(response, SecurityPortalTokenResponse.class);

        } catch (IOException e) {
            throw new SecurityPortalException(e);
        } finally {
            httpPost.releaseConnection();
        }
    }

    private Principal doAuthz(String loginName, String token) throws SecurityPortalException {

        if (oidcMetadata == null) {
            oidcMetadata = getOidcInformation();
        }

        LOGGER.info("Authenticate User");

        SecurityPortalTokenResponse tokens = exchangeToken(configuration.getClientId(), token);

        SecurityPortalUser user = getUserInformation(tokens);
        SecurityPortalRolesResponse roles = getUserRoles(tokens);

        LOGGER.info("Creating Principal");
        Principal principal = new Principal();

        principal.setOauthToken(tokens.getAccessToken().toCharArray());
        principal.setUsername(user.getUserAccount());
        principal.setRoles(Arrays.asList(roles.getRoles()).stream().map(r -> r.getName()).collect(Collectors.toSet()));

        return principal;
    }

    public Principal authz(String login, String token) throws SecurityPortalException {

        String cacheKey = token;
        Principal cachedPrincipal = tokenToPrincipalCache.getIfPresent(cacheKey);
        if (cachedPrincipal != null) {
            LOGGER.info("Using cached principal for login: {}", cachedPrincipal.getUsername());
            return cachedPrincipal;
        }

        // Check if this token was previously used but returned an error code
        Integer cachedErrorCode = tokenToErrorCodeCache.getIfPresent(cacheKey);
        if (cachedErrorCode != null) {
            LOGGER.info("Token cached as invalid. Not authenticating...");
            throw new AuthenticationException("Token already cached with error", cachedErrorCode, token);
        }

        // If it reaches this point, then it means we don't have this token cached.
        // Authenticating user

        try {
            Principal principal = doAuthz(login, token);
            tokenToPrincipalCache.put(cacheKey, principal);

            return principal;
        } catch (AuthenticationException e) {
            tokenToErrorCodeCache.put(cacheKey, 401);
            LOGGER.info("Caching token due to an authentication error");
            throw e;
        }
    }

}
