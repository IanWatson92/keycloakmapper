package io.iw.keycloakmapper;

import org.keycloak.OAuth2Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;
import java.util.ArrayList;
import java.util.List;
import org.jboss.logging.Logger;
import java.util.List;
import java.util.Arrays;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.models.UserModel;
import java.util.Collection;

public class KeycloakMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    protected static Logger log = Logger.getLogger(KeycloakMapper.class);

    static {
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, KeycloakMapper.class);
    }

    @Override
    public String getDisplayCategory() {
        return "Token mapper";
    }

    @Override
    public String getDisplayType() {
        return "Project mapper";
    }

    @Override
    public String getHelpText() {
        return "Maps a project to the access token to be used for ABAC'd applications";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return "project-mapper";
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession) {
        String scopes = userSession.getAuthenticatedClientSessionByClient("7f801643-a755-427f-b91a-e7a4775417c2").getNote(OAuth2Constants.SCOPE);
        List<String> scopesList = Arrays.asList(scopes.split(" "));
        List<String> projectRequested = new ArrayList<>();
        scopesList.forEach((scope) -> {
          if (scope.startsWith("project")) {            
            projectRequested.add(scope);
          }
        });

        if (projectRequested.size() == 1) {
          // check if user is part of the requested project via some means such as an ldap lookup or group check
          String projectValue = projectRequested.get(0).split(":")[1];
          OIDCAttributeMapperHelper.mapClaim(token, mappingModel, projectValue);

        }
    }
}
