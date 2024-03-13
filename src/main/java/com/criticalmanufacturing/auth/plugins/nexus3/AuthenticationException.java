package com.criticalmanufacturing.auth.plugins.nexus3;

public class AuthenticationException extends SecurityPortalException {

    private String internalMessage;

    private String handleToken(String token) {
        // Token may be null, deal with that case
        String maskedToken;
        if (token == null) {
            maskedToken = "Anonymous";
        } else if (token.length() > 4) {
            maskedToken = token.substring(token.length() - 4);
        } else {
            maskedToken = token;
        }

        return maskedToken;
    }

    public AuthenticationException(String message, int statusCode) {
        super("", statusCode);

        this.internalMessage = message;
    }

    public AuthenticationException(String message, int code, String token) {
        this("", code);

        this.internalMessage = message +
                " | Status Code: " + code +
                " | Token: ***" + handleToken(token);
    }

    public AuthenticationException(Throwable cause) {
        super(cause);
    }

    @Override
    public String getMessage() {
        return this.internalMessage;
    }
}
