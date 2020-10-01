package com.criticalmanufacturing.auth.plugins.nexus3.api;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class SecurityPortalRole {
    private String id;
    private String name;
    private String description;
    private boolean isScope;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public boolean isScope() {
        return isScope;
    }

    public void setScope(boolean scope) {
        isScope = scope;
    }
}
