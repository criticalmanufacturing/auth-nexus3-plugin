package com.criticalmanufacturing.auth.plugins.nexus3.api;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class SecurityPortalRolesResponse {

    @JsonProperty("body")
    private SecurityPortalRole[] roles;

    public SecurityPortalRole[] getRoles() {
        return roles;
    }

    public void setRoles(SecurityPortalRole[] roles) {
        this.roles = roles;
    }
}
