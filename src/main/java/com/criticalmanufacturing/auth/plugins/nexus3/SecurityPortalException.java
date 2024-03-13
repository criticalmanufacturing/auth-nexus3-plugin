package com.criticalmanufacturing.auth.plugins.nexus3;

public class SecurityPortalException extends Exception {
    private int statusCode;

    public int getStatusCode() {
        return statusCode;
    }

    public SecurityPortalException(String message) {
        super(message);
    }

    public SecurityPortalException(String message, int statusCode) {
        super(message);

        this.statusCode = statusCode;
    }

    public SecurityPortalException(Throwable cause) {
        super(cause);
    }
}
