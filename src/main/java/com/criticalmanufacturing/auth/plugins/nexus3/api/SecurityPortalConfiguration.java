package com.criticalmanufacturing.auth.plugins.nexus3.api;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Named;
import javax.inject.Singleton;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.Properties;

@Singleton
@Named
public class SecurityPortalConfiguration {

    private static final String CONFIG_FILE = "criticalmanufacturing-oidc.properties";
    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityPortalClient.class);

    private static final String METADATA_URL_KEY = "metadata.url";
    private static final String PRINCIPAL_CACHE_TTL_KEY = "principal.cache.ttl";
    private static final String REQUEST_CONNECT_TIMEOUT = "request.timeout.connect";
    private static final String REQUEST_CONNECTION_REQUEST_TIMEOUT = "request.timeout.connection-request";
    private static final String REQUEST_SOCKET_TIMEOUT = "request.timeout.socket";
    private static final String CLIENT_ID_KEY = "clientid";

    // Default values
    private static final String DEFAULT_CLIENT_ID = "Applications";
    private static final String DEFAULT_METADATA_URL = "https://security.criticalmanufacturing.com/tenant/CustomerPortal/.well-known/openid-configuration";
    private static final int DEFAULT_REQUEST_CONNECTION_REQUEST_TIMEOUT = -1;
    private static final int DEFAULT_REQUEST_SOCKET_TIMEOUT = -1;
    private static final int DEFAULT_REQUEST_CONNECT_TIMEOUT = -1;
    private static final Duration DEFAULT_PRINCIPAL_CACHE_TTL = Duration.ofMinutes(1);


    private Properties configuration;

    public SecurityPortalConfiguration() {
        configuration = new Properties();

        try {
            configuration.load(Files.newInputStream(Paths.get(".", "etc", CONFIG_FILE)));
        } catch (IOException e) {
            LOGGER.warn("Error reading Critical Manufacturing OIDC properties, falling back to default configuration", e);
        }
    }

    public String getClientId() {
        return configuration.getOrDefault(CLIENT_ID_KEY, DEFAULT_CLIENT_ID).toString();
    }

    public String getMetadataUrl() {
        return configuration.getOrDefault(METADATA_URL_KEY, DEFAULT_METADATA_URL).toString();
    }

    public Duration getPrincipalCacheTtl() {
        return Duration.parse(configuration.getProperty(PRINCIPAL_CACHE_TTL_KEY, DEFAULT_PRINCIPAL_CACHE_TTL.toString()));
    }

    public int getRequestConnectTimeout() {
        return Integer.parseInt(configuration.getProperty(REQUEST_CONNECT_TIMEOUT, String.valueOf(DEFAULT_REQUEST_CONNECT_TIMEOUT)));
    }

    public Integer getRequestConnectionRequestTimeout() {
        return Integer.parseInt(configuration.getProperty(REQUEST_CONNECTION_REQUEST_TIMEOUT, String.valueOf(DEFAULT_REQUEST_CONNECTION_REQUEST_TIMEOUT)));
    }

    public Integer getRequestSocketTimeout() {
        return Integer.parseInt(configuration.getProperty(REQUEST_SOCKET_TIMEOUT, String.valueOf(DEFAULT_REQUEST_SOCKET_TIMEOUT)));
    }

}
