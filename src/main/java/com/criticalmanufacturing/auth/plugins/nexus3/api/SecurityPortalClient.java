package com.criticalmanufacturing.auth.plugins.nexus3.api;

import com.criticalmanufacturing.auth.plugins.nexus3.AuthenticationException;
import com.criticalmanufacturing.auth.plugins.nexus3.Principal;
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


    private OidcMetadata getOidcInformation() throws AuthenticationException {
        LOGGER.info("Fetching OIDC information...");
        HttpGet oidcRequest = new HttpGet(this.configuration.getMetadataUrl());

        try {
            HttpResponse response = this.client.execute(oidcRequest);

            if (response.getStatusLine().getStatusCode() != 200) {
                LOGGER.warn("Unable to fetch OIDC metadata from {}", response.getStatusLine().getStatusCode());
                throw new AuthenticationException("OIDC metadata fetch error");
            }

            OidcMetadata metadata = serializeObject(response, OidcMetadata.class);

            return metadata;

        } catch (IOException e) {
            throw new AuthenticationException(e);
        } finally {
            oidcRequest.releaseConnection();
        }

    }

    private SecurityPortalUser getUserInformation(SecurityPortalTokenResponse tokens) throws  AuthenticationException {

        LOGGER.info("Fetching User Information");

        HttpGet httpGetUser = new HttpGet(this.oidcMetadata.getUserinfoEndpoint());
        httpGetUser.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + tokens.getAccessToken());

        try {
            HttpResponse response = this.client.execute(httpGetUser);

            if (response.getStatusLine().getStatusCode() != 200) {
                LOGGER.warn("Unable to retrieve user information. Status code {}", response.getStatusLine().getStatusCode());
                throw new AuthenticationException("Unable to retrieve user information");
            }

            SecurityPortalUser securityPortalUser = serializeObject(response, SecurityPortalUser.class);

            return securityPortalUser;

        } catch (IOException e) {
            throw new AuthenticationException(e);
        } finally {
            httpGetUser.releaseConnection();
        }
    }

    private SecurityPortalRolesResponse getUserRoles(SecurityPortalTokenResponse tokens) throws AuthenticationException {
        LOGGER.info("Fetching User Roles");

        HttpGet httpGetUserRoles = new HttpGet(this.oidcMetadata.getUserinfoEndpoint() + "/roles");
        httpGetUserRoles.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + tokens.getAccessToken());

        try {
            HttpResponse response = this.client.execute(httpGetUserRoles);

            if (response.getStatusLine().getStatusCode() != 200) {
                LOGGER.warn("Unable to retrieve user roles. Status code {}", response.getStatusLine().getStatusCode());
                throw new AuthenticationException("Unable to retrieve user roles");
            }

            SecurityPortalRolesResponse securityPortalRolesResponse = serializeObject(response, SecurityPortalRolesResponse.class);

            return securityPortalRolesResponse;

        } catch (IOException e) {
            throw new AuthenticationException(e);
        } finally {
            httpGetUserRoles.releaseConnection();
        }
    }

    private SecurityPortalTokenResponse exchangeToken(String clientId, String token) throws AuthenticationException {
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

            if (response.getStatusLine().getStatusCode() != 200) {
                LOGGER.warn("Unable to exchange token from {}", response.getStatusLine().getStatusCode());
                throw new AuthenticationException("Exchange tokens error");
            }

            LOGGER.info("Tokens exchanged. Handling response...");
            SecurityPortalTokenResponse tokens = serializeObject(response, SecurityPortalTokenResponse.class);

            return tokens;

        } catch (IOException e) {
            throw new AuthenticationException(e);
        } finally {
            httpPost.releaseConnection();
        }
    }

    private Principal doAuthz(String loginName, String token) throws AuthenticationException {

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

    public Principal authz(String login, String token) throws AuthenticationException {

         String cacheKey = token;
        Principal cached = tokenToPrincipalCache.getIfPresent(cacheKey);
        if (cached != null) {
            LOGGER.info("Using cached principal for login: {}", cached.getUsername());
            return cached;
        } else {
             Principal principal = doAuthz(login, token);
            tokenToPrincipalCache.put(cacheKey, principal);
            return principal;
        }
    }

}
