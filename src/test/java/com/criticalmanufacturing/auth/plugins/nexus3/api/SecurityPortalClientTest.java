package com.criticalmanufacturing.auth.plugins.nexus3.api;

import com.criticalmanufacturing.auth.plugins.nexus3.AuthenticationException;
import com.criticalmanufacturing.auth.plugins.nexus3.Principal;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpRequestBase;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

@RunWith(MockitoJUnitRunner.class)
public class SecurityPortalClientTest {

    private final MockSecurityPortalConfiguration config = new MockSecurityPortalConfiguration();
    private final ObjectMapper mapper = new ObjectMapper();

    private HttpClient fullyFunctionalMockClient() throws IOException {
        HttpClient mockClient = Mockito.mock(HttpClient.class);
        mockResponsesForSecurityPortalAuthRequest(mockClient);
        return mockClient;
    }

    private HttpClient invalidTokenMockClient() throws IOException {
        HttpClient mockClient = Mockito.mock(HttpClient.class);
        mockResponsesForSecurityPortalAuthRequest401(mockClient);
        return mockClient;
    }

    private SecurityPortalUser mockUser(String username) {
        SecurityPortalUser spUser = new SecurityPortalUser();
        spUser.setUserAccount(username);

        return spUser;
    }

    private OidcMetadata mockMetadata() {
        OidcMetadata metadata = new OidcMetadata();
        metadata.setIssuer("http://localhost/tenant/Development");
        metadata.setUserinfoEndpoint("http://localhost/api/users/me");
        metadata.setTokenEndpoint("http://localhost/api/tenant/Development/oauth2/token");

        return metadata;
    }

    private SecurityPortalTokenResponse mockToken() {
        SecurityPortalTokenResponse mockResponse = new SecurityPortalTokenResponse();
        mockResponse.setAccessToken("abc");
        mockResponse.setRefreshToken("refresh_abc");

        return mockResponse;
    }

    private SecurityPortalRolesResponse mockRoles() {
        SecurityPortalRolesResponse mockResponse = new SecurityPortalRolesResponse();
        SecurityPortalRole role = new SecurityPortalRole();
        role.setName("Administrator");

        mockResponse.setRoles(new SecurityPortalRole[] {role });

        return mockResponse;
    }

    private HttpResponse createMock401Response() throws IOException {
        HttpResponse mockOrgResponse = Mockito.mock(HttpResponse.class, Mockito.RETURNS_DEEP_STUBS);

        Mockito.when(mockOrgResponse.getStatusLine().getStatusCode()).thenReturn(401);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        mapper.writeValue(baos, "Invalid User");
        byte[] data = baos.toByteArray();
        Mockito.when(mockOrgResponse.getEntity().getContent()).thenReturn(new ByteArrayInputStream(data));

        return mockOrgResponse;
    }

    private HttpResponse createMock200Response(Object entity) throws IOException {
        HttpResponse mockOrgResponse = Mockito.mock(HttpResponse.class, Mockito.RETURNS_DEEP_STUBS);

        Mockito.when(mockOrgResponse.getStatusLine().getStatusCode()).thenReturn(200);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        mapper.writeValue(baos, entity);
        byte[] data = baos.toByteArray();
        Mockito.when(mockOrgResponse.getEntity().getContent()).thenReturn(new ByteArrayInputStream(data));

        return mockOrgResponse;
    }

    private HttpResponse answerOnInvocationError(InvocationOnMock invocationOnMock, HttpResponse mockUserResponse) throws IOException {

        OidcMetadata metadata = mockMetadata();

        String uriString = ((HttpRequestBase) invocationOnMock.getArguments()[0]).getURI().toString();
        if (uriString.equals(config.getMetadataUrl())) {
            HttpResponse mockTeamResponse = createMock200Response(metadata);
            return mockTeamResponse;
        } else if (uriString.equals(metadata.getTokenEndpoint())) {
            return createMock401Response();
        } else if (uriString.equals(metadata.getUserinfoEndpoint())) {
            return createMock401Response();
        } else if (uriString.equals(metadata.getUserinfoEndpoint() + "/roles")) {
            return createMock401Response();
        }

        return null;
    }

    private HttpResponse answerOnInvocationSuccess(InvocationOnMock invocationOnMock, HttpResponse mockUserResponse) throws IOException {

        OidcMetadata metadata = mockMetadata();

        String uriString = ((HttpRequestBase) invocationOnMock.getArguments()[0]).getURI().toString();
        if (uriString.equals(config.getMetadataUrl())) {
            HttpResponse mockTeamResponse = createMock200Response(metadata);
            return mockTeamResponse;
        } else if (uriString.equals(metadata.getTokenEndpoint())) {
            return createMock200Response(mockToken());
        } else if (uriString.equals(metadata.getUserinfoEndpoint())) {
            return mockUserResponse;
        } else if (uriString.equals(metadata.getUserinfoEndpoint() + "/roles")) {
            return createMock200Response(mockRoles());
        }

        return null;
    }

    private void mockResponsesForSecurityPortalAuthRequest(HttpClient mockClient) throws IOException {
        HttpResponse mockUserResponse = createMock200Response(mockUser("JSilva"));
        Mockito.when(mockClient.execute(Mockito.any())).thenAnswer(invocationOnMock -> answerOnInvocationSuccess(invocationOnMock, mockUserResponse));
    }

    private void mockResponsesForSecurityPortalAuthRequest401(HttpClient mockClient) throws IOException {
        HttpResponse mockUserResponse = createMock401Response();
        Mockito.when(mockClient.execute(Mockito.any())).thenAnswer(invocationOnMock -> answerOnInvocationError(invocationOnMock, mockUserResponse));
    }

    @Test
    public void shouldDoMockAuthz() throws Exception {
        HttpClient mockClient = fullyFunctionalMockClient();

        SecurityPortalClient clientToTest = new SecurityPortalClient(mockClient, new MockSecurityPortalConfiguration());
        Principal principal = clientToTest.authz("JSilva", "12312313");

        Assert.assertEquals("JSilva", principal.getUsername());
        Assert.assertEquals(1, principal.getRoles().size());
        Assert.assertEquals("Administrator", principal.getRoles().stream().findFirst().get());

    }

    @Test
    public void shouldCacheInvalidTokens() throws Exception {
        String userName = "JSilva";
        String token = "12312313";

        HttpClient mockClient = invalidTokenMockClient();

        SecurityPortalClient clientToTest = new SecurityPortalClient(mockClient, new MockSecurityPortalConfiguration());
        try {
            clientToTest.authz(userName, token);
            Assert.fail("Authz method should throw an AuthenticationException");
        } catch (AuthenticationException e) {
            boolean messageFromCache = e.getMessage().startsWith("Token already cached with error");
            Assert.assertFalse(messageFromCache);
        }

        try {
            clientToTest.authz(userName, token);
            Assert.fail("Authz method should throw an AuthenticationException");
        } catch (AuthenticationException e) {
            boolean messageFromCache = e.getMessage().startsWith("Token already cached with error");
            Assert.assertTrue(messageFromCache);
        }
    }

//    @Test
//    public void shouldDoAuthInCustomerPortal() throws Exception {
//
//        MockSecurityPortalConfiguration config = new MockSecurityPortalConfiguration();
//        config.setClientId("MES");
//        config.setMetadataUrl("http://localhost:11000/tenant/MesDevelopment/.well-known/openid-configuration");
//
//        String userAccount = "";
//        String token = "this is a test token";
//
//        SecurityPortalClient clientToTest = new SecurityPortalClient(null, config);
//        Principal principal = clientToTest.authz(userAccount, token);
//
//        Assert.assertEquals(principal.getUsername(), userAccount);
//    }
}
