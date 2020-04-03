package io.iw.keycloakmapper;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;
import org.keycloak.services.ServicesLogger;
import org.jboss.logging.Logger;

public class UtilMapper {

  protected static Logger log = Logger.getLogger(UtilMapper.class);

  public static final String TOKEN_CLAIM_NAME = "claim.name";
  
  public static final String TOKEN_CLAIM_NAME_LABEL = "tokenClaimName.label";
  
  public static final String TOKEN_CLAIM_NAME_TOOLTIP = "tokenClaimName.tooltip";
  
  public static final String JSON_TYPE = "jsonType.label";
  
  public static final String JSON_TYPE_TOOLTIP = "jsonType.tooltip";
  
  public static final String INCLUDE_IN_ACCESS_TOKEN = "access.token.claim";
  
  public static final String INCLUDE_IN_ACCESS_TOKEN_LABEL = "includeInAccessToken.label";
  
  public static final String INCLUDE_IN_ACCESS_TOKEN_HELP_TEXT = "includeInAccessToken.tooltip";
  
  public static final String INCLUDE_IN_ID_TOKEN = "id.token.claim";
  
  public static final String INCLUDE_IN_ID_TOKEN_LABEL = "includeInIdToken.label";
  
  public static final String INCLUDE_IN_ID_TOKEN_HELP_TEXT = "includeInIdToken.tooltip";
  
  public static final String INCLUDE_IN_USERINFO = "userinfo.token.claim";
  
  public static final String INCLUDE_IN_USERINFO_LABEL = "includeInUserInfo.label";
  
  public static final String INCLUDE_IN_USERINFO_HELP_TEXT = "includeInUserInfo.tooltip";
  
  public static Object mapAttributeValue(ProtocolMapperModel mappingModel, Object attributeValue) {
    if (attributeValue == null)
      return null; 
    if (attributeValue instanceof Collection) {
      Collection<Object> valueAsList = (Collection<Object>)attributeValue;
      if (valueAsList.isEmpty())
        return null; 
      if (isMultivalued(mappingModel)) {
        List<Object> result = new ArrayList();
        for (Object valueItem : valueAsList)
          result.add(mapAttributeValue(mappingModel, valueItem)); 
        return result;
      } 
      if (valueAsList.size() > 1)
        ServicesLogger.LOGGER.multipleValuesForMapper(attributeValue.toString(), mappingModel.getName()); 
      attributeValue = valueAsList.iterator().next();
    } 
    String type = (String)mappingModel.getConfig().get("jsonType.label");
    Object converted = convertToType(type, attributeValue);
    return (converted != null) ? converted : attributeValue;
  }
  
  private static <X, T> List<T> transform(List<X> attributeValue, Function<X, T> mapper) {
    return (List<T>)attributeValue.stream()
      .filter(Objects::nonNull)
      .<T>map(mapper)
      .collect(Collectors.toList());
  }


  
  private static Object convertToType(String type, Object attributeValue) {
    Boolean booleanObject;
    Long longObject;
    Integer intObject;
    if (type == null || attributeValue == null)
      return attributeValue; 
    switch (type) {
      case "boolean":
        booleanObject = getBoolean(attributeValue);
        if (booleanObject != null)
          return booleanObject; 
        if (attributeValue instanceof List)
          return transform((List)attributeValue, UtilMapper::getBoolean);
        throw new RuntimeException("cannot map type for token claim");
      case "String":
        if (attributeValue instanceof String)
          return attributeValue; 
        if (attributeValue instanceof List)
          return transform((List)attributeValue, UtilMapper::getString);
        return attributeValue.toString();
      case "long":
        longObject = getLong(attributeValue);
        if (longObject != null)
          return longObject; 
        if (attributeValue instanceof List)
          return transform((List)attributeValue, UtilMapper::getLong);
        throw new RuntimeException("cannot map type for token claim");
      case "int":
        intObject = getInteger(attributeValue);
        if (intObject != null)
          return intObject; 
        if (attributeValue instanceof List)
          return transform((List)attributeValue, UtilMapper::getInteger);
        throw new RuntimeException("cannot map type for token claim");
    } 
    return null;
  }
  
  private static String getString(Object attributeValue) {
    return attributeValue.toString();
  }
  
  private static Long getLong(Object attributeValue) {
    if (attributeValue instanceof Long)
      return (Long)attributeValue; 
    if (attributeValue instanceof String)
      return Long.valueOf((String)attributeValue); 
    return null;
  }
  
  private static Integer getInteger(Object attributeValue) {
    if (attributeValue instanceof Integer)
      return (Integer)attributeValue; 
    if (attributeValue instanceof String)
      return Integer.valueOf((String)attributeValue); 
    return null;
  }
  
  private static Boolean getBoolean(Object attributeValue) {
    if (attributeValue instanceof Boolean)
      return (Boolean)attributeValue; 
    if (attributeValue instanceof String)
      return Boolean.valueOf((String)attributeValue); 
    return null;
  }
  
  private static final Pattern CLAIM_COMPONENT = Pattern.compile("^((\\\\.|[^\\\\.])+?)\\.");
  
  private static final Pattern BACKSLASHED_CHARACTER = Pattern.compile("\\\\(.)");
  
  public static List<String> splitClaimPath(String claimPath) {
    LinkedList<String> claimComponents = new LinkedList<>();
    Matcher m = CLAIM_COMPONENT.matcher(claimPath);
    int start = 0;
    while (m.find()) {
      claimComponents.add(BACKSLASHED_CHARACTER.matcher(m.group(1)).replaceAll("$1"));
      start = m.end();
      m.region(start, claimPath.length());
    } 
    if (claimPath.length() > start)
      claimComponents.add(BACKSLASHED_CHARACTER.matcher(claimPath.substring(start)).replaceAll("$1")); 
    return claimComponents;
  }
  
  public static void mapClaim(IDToken token, ProtocolMapperModel mappingModel, Object attributeValue) {
    log.warn("Entering mapClaim");
    attributeValue = mapAttributeValue(mappingModel, attributeValue);
    log.warn("AttributeValue is " + attributeValue);
    if (attributeValue == null)
      return; 
    String protocolClaim = (String)mappingModel.getConfig().get("claim.name");
    if (protocolClaim == null)
      return;
    log.warn("Protocol claim is " + protocolClaim);
    List<String> split = splitClaimPath(protocolClaim);
    int length = split.size();
    int i = 0;
    Map<String, Object> jsonObject = token.getOtherClaims();
    log.warn("json other claim is " + jsonObject);
    for (String component : split) {
      i++;
      if (i == length) {
        jsonObject.put(component, attributeValue);
        continue;
      }
      log.warn("Before nested, component is " + component);
      Map<String, Object> nested = (Map<String, Object>)jsonObject.get(component);
      log.warn("After nested");
      if (nested == null) {
        nested = new HashMap<>();
        jsonObject.put(component, nested);
      } 
      jsonObject = nested;
    } 
  }
  
  public static ProtocolMapperModel createClaimMapper(String name, String userAttribute, String tokenClaimName, String claimType, boolean accessToken, boolean idToken, String mapperId) {
    return createClaimMapper(name, userAttribute, tokenClaimName, claimType, accessToken, idToken, true, mapperId);
  }
  
  public static ProtocolMapperModel createClaimMapper(String name, String userAttribute, String tokenClaimName, String claimType, boolean accessToken, boolean idToken, boolean userinfo, String mapperId) {
    ProtocolMapperModel mapper = new ProtocolMapperModel();
    mapper.setName(name);
    mapper.setProtocolMapper(mapperId);
    mapper.setProtocol("openid-connect");
    Map<String, String> config = new HashMap<>();
    config.put("user.attribute", userAttribute);
    config.put("claim.name", tokenClaimName);
    config.put("jsonType.label", claimType);
    if (accessToken)
      config.put("access.token.claim", "true"); 
    if (idToken)
      config.put("id.token.claim", "true"); 
    if (userinfo)
      config.put("userinfo.token.claim", "true"); 
    mapper.setConfig(config);
    return mapper;
  }
  
  public static boolean includeInIDToken(ProtocolMapperModel mappingModel) {
    return "true".equals(mappingModel.getConfig().get("id.token.claim"));
  }
  
  public static boolean includeInAccessToken(ProtocolMapperModel mappingModel) {
    return "true".equals(mappingModel.getConfig().get("access.token.claim"));
  }
  
  public static boolean isMultivalued(ProtocolMapperModel mappingModel) {
    return "true".equals(mappingModel.getConfig().get("multivalued"));
  }
  
  public static boolean includeInUserInfo(ProtocolMapperModel mappingModel) {
    String includeInUserInfo = (String)mappingModel.getConfig().get("userinfo.token.claim");
    if (includeInUserInfo == null && includeInIDToken(mappingModel))
      return true; 
    return "true".equals(includeInUserInfo);
  }
  
  public static void addAttributeConfig(List<ProviderConfigProperty> configProperties, Class<? extends ProtocolMapper> protocolMapperClass) {
    addTokenClaimNameConfig(configProperties);
    addJsonTypeConfig(configProperties);
    addIncludeInTokensConfig(configProperties, protocolMapperClass);
  }
  
  public static void addTokenClaimNameConfig(List<ProviderConfigProperty> configProperties) {
    ProviderConfigProperty property = new ProviderConfigProperty();
    property.setName("claim.name");
    property.setLabel("tokenClaimName.label");
    property.setType("String");
    property.setHelpText("tokenClaimName.tooltip");
    configProperties.add(property);
  }
  
  public static void addJsonTypeConfig(List<ProviderConfigProperty> configProperties) {
    ProviderConfigProperty property = new ProviderConfigProperty();
    property.setName("jsonType.label");
    property.setLabel("jsonType.label");
    List<String> types = new ArrayList<>(3);
    types.add("String");
    types.add("long");
    types.add("int");
    types.add("boolean");
    property.setType("List");
    property.setOptions(types);
    property.setHelpText("jsonType.tooltip");
    configProperties.add(property);
  }
  
  public static void addIncludeInTokensConfig(List<ProviderConfigProperty> configProperties, Class<? extends ProtocolMapper> protocolMapperClass) {
    if (OIDCIDTokenMapper.class.isAssignableFrom(protocolMapperClass)) {
      ProviderConfigProperty property = new ProviderConfigProperty();
      property.setName("id.token.claim");
      property.setLabel("includeInIdToken.label");
      property.setType("boolean");
      property.setDefaultValue("true");
      property.setHelpText("includeInIdToken.tooltip");
      configProperties.add(property);
    } 
    if (OIDCAccessTokenMapper.class.isAssignableFrom(protocolMapperClass)) {
      ProviderConfigProperty property = new ProviderConfigProperty();
      property.setName("access.token.claim");
      property.setLabel("includeInAccessToken.label");
      property.setType("boolean");
      property.setDefaultValue("true");
      property.setHelpText("includeInAccessToken.tooltip");
      configProperties.add(property);
    } 
    if (UserInfoTokenMapper.class.isAssignableFrom(protocolMapperClass)) {
      ProviderConfigProperty property = new ProviderConfigProperty();
      property.setName("userinfo.token.claim");
      property.setLabel("includeInUserInfo.label");
      property.setType("boolean");
      property.setDefaultValue("true");
      property.setHelpText("includeInUserInfo.tooltip");
      configProperties.add(property);
    } 
  }
}

