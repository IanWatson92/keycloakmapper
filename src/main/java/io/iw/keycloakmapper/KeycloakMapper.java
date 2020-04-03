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

    public KeycloakMapper() {
      log.warn(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> mapper called!");
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
        log.warn(">>>>>>>>>>>>>>>>>>>>>>>>> Set Claim invoked!");
        String scopes = userSession.getAuthenticatedClientSessionByClient("7f801643-a755-427f-b91a-e7a4775417c2").getNote(OAuth2Constants.SCOPE);
        List<String> scopesList = Arrays.asList(scopes.split(" "));
        log.warn(">>>>>>>>>>>>>>>>>>>>>>> Scopes are " + scopesList.toString());
        List<String> projectRequested = new ArrayList<>();
        scopesList.forEach((scope) -> {
          log.warn(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> scope iterated is " + scope);
          if (scope.startsWith("project")) {            
            projectRequested.add(scope);
          }
        });

        log.warn("Size of projectRequested is " + projectRequested.size());
        log.warn("Content is " + projectRequested.toString());
        if (projectRequested.size() == 1) {
          // check if user is part of the requested project
          // here we just assume they are
          String projectValue = projectRequested.get(0).split(":")[1];
          log.warn(">>>>>>>>>>>>> projectValue " + projectValue);
          OIDCAttributeMapperHelper.mapClaim(token, mappingModel, projectValue);

        }

//        OIDCAttributeMapperHelper.mapClaim(token, mappingModel, "hello world");
    }

    public static void mapClaim(IDToken token, ProtocolMapperModel mappingModel, Object attributeValue) {
    attributeValue = mapAttributeValue(mappingModel, attributeValue);
    if (attributeValue == null)
      return; 
    String protocolClaim = (String)mappingModel.getConfig().get("claim.name");
    if (protocolClaim == null)
      return; 
    List<String> split = splitClaimPath(protocolClaim);
    int length = split.size();
    int i = 0;
    Map<String, Object> jsonObject = token.getOtherClaims();
    for (String component : split) {
      i++;
      if (i == length) {
        jsonObject.put(component, attributeValue);
        continue;
      } 
      Map<String, Object> nested = (Map<String, Object>)jsonObject.get(component);
      if (nested == null) {
        nested = new HashMap<>();
        jsonObject.put(component, nested);
      } 
      jsonObject = nested;
    } 
  }

}
