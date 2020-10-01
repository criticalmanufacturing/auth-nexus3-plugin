package com.criticalmanufacturing.auth.plugins.nexus3;

import com.criticalmanufacturing.auth.plugins.nexus3.api.SecurityPortalClient;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.*;
import org.apache.shiro.authc.pam.UnsupportedTokenException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.eclipse.sisu.Description;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import java.util.stream.Collectors;

@Singleton
@Named
@Description("Critical Manufacturing Authentication Realm")
public class AuthenticatingRealm extends AuthorizingRealm {

    private SecurityPortalClient securityPortalClient;

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticatingRealm.class);

    public static final String NAME = AuthenticatingRealm.class.getName();

    @Inject
    public AuthenticatingRealm(SecurityPortalClient securityPortalClient) {
        this.securityPortalClient = securityPortalClient;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.apache.shiro.realm.CachingRealm#getName()
     */
    @Override
    public String getName() {
        return NAME;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.apache.shiro.realm.AuthorizingRealm#onInit()
     */
    @Override
    protected void onInit() {
        super.onInit();
        LOGGER.info("Security Portal OIDC Realm initialized");
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * org.apache.shiro.realm.AuthorizingRealm#doGetAuthorizationInfo(org.apache
     * .shiro.subject.PrincipalCollection)
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        Principal user = (Principal) principals.getPrimaryPrincipal();
        LOGGER.info("doGetAuthorizationInfo for user {} with roles {}", user.getUsername(), user.getRoles().stream().collect(Collectors.joining(", ")));
        return new SimpleAuthorizationInfo(user.getRoles());

    }

    /*
     * (non-Javadoc)
     *
     * @see
     * org.apache.shiro.realm.AuthenticatingRealm#doGetAuthenticationInfo(org.
     * apache.shiro.authc.AuthenticationToken)
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        if (!(token instanceof UsernamePasswordToken)) {
            throw new UnsupportedTokenException(String.format("Token of type %s  is not supported. A %s is required.",
                    token.getClass().getName(), UsernamePasswordToken.class.getName()));
        }

        UsernamePasswordToken t = (UsernamePasswordToken) token;
        LOGGER.info("doGetAuthenticationInfo for {}", t.getUsername());

        Principal authenticatedPrincipal;
        try {
            authenticatedPrincipal = securityPortalClient.authz(t.getUsername(), new String(t.getPassword()));
            LOGGER.info("Successfully authenticated {}", t.getUsername());
        } catch (com.criticalmanufacturing.auth.plugins.nexus3.AuthenticationException e) {
            LOGGER.warn("Failed authentication", e);
            return null;
        }

        return new SimpleAuthenticationInfo(authenticatedPrincipal, token.getCredentials(), NAME);
    }
}
