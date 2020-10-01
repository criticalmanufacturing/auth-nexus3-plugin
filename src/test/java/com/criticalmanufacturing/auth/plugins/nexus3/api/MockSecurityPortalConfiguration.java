package com.criticalmanufacturing.auth.plugins.nexus3.api;

public class MockSecurityPortalConfiguration extends SecurityPortalConfiguration {

    private String clientId = "nexus";

    private String metadataUrl = "http://localhost:11000/tenant/MesDevelopment/.well-known/openid-configuration";

    @Override
    public String getClientId() {
        return clientId;
    }

    @Override
    public String getMetadataUrl() {
        return metadataUrl;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public void setMetadataUrl(String metadataUrl) {
        this.metadataUrl = metadataUrl;
    }
}
