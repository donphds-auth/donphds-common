package com.donphds.common.auth.token;

import static com.donphds.common.auth.token.IdTokenFactory.NICKNAME;
import static com.donphds.common.auth.token.IdTokenFactory.NONCE;
import static com.donphds.common.auth.token.IdTokenFactory.PICTURE;

import com.donphds.common.auth.Audience;
import com.donphds.common.auth.Issuer;
import com.donphds.common.exception.KeyException;
import com.donphds.common.exception.TokenException;
import com.google.common.base.Splitter;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.apache.commons.lang3.StringUtils;
import org.jose4j.base64url.Base64Url;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.OctetSequenceJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.JwksDecryptionKeyResolver;
import org.jose4j.lang.JoseException;

public class AccessTokenFactory extends TokenFactory<AccessToken> {

  private static final String SCOPE = "scope";

  public AccessTokenFactory(Issuer issuer) {
    super(issuer);
  }

  public String issue(AccessToken accessToken, Audience audience) throws JoseException {
    return this.sign(generate(accessToken, audience), audience::getSignSecret);
  }

  public JwtClaims generate(AccessToken accessToken, Audience audience) throws JoseException {
    JwtClaims jwtClaims = super.generate(accessToken, audience);
    String encryptSecrets = audience.getEncryptSecrets();
    if (StringUtils.isBlank(encryptSecrets)) {
      throw new KeyException("invalid_encrypt_key");
    }
    JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk(Base64Url.decodeToUtf8String(encryptSecrets));
    if (jsonWebKey instanceof OctetSequenceJsonWebKey) {
      OctetSequenceJsonWebKey octetSequenceJsonWebKey = (OctetSequenceJsonWebKey) jsonWebKey;
      JsonWebEncryption encryption = new JsonWebEncryption();
      encryption.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);
      encryption.setEncryptionMethodHeaderParameter(
          ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
      encryption.setKey(octetSequenceJsonWebKey.getKey());
      encryption.setKeyIdHeaderValue(octetSequenceJsonWebKey.getKeyId());
      JwtClaims subClaims = new JwtClaims();
      subClaims.setStringClaim(SUB, accessToken.getSub());
      subClaims.setStringClaim(NICKNAME, accessToken.getNickname());
      subClaims.setStringClaim(PICTURE, accessToken.getPicture());
      if (StringUtils.isNotBlank(accessToken.getNonce())) {
        subClaims.setStringClaim(NONCE, accessToken.getNickname());
      }
      encryption.setPayload(subClaims.toJson());
      jwtClaims.setSubject(encryption.getCompactSerialization());
    }
    jwtClaims.setClaim(SCOPE, accessToken.getScope());
    return jwtClaims;
  }

  public JwtClaims verify(String token, Audience audience) {
    try {
      JwtClaims claims = super.verify(token, audience);
      if (claims.hasClaim(SUB)) {
        List<String> decryptKeys =
            Optional.ofNullable(audience.getDecryptSecrets()).orElse(new ArrayList<>());
        List<JsonWebKey> decryptJwks = this.buildJwks(decryptKeys);
        JwtConsumer decryptConsumer =
            new JwtConsumerBuilder()
                .setDisableRequireSignature()
                .setDecryptionKeyResolver(new JwksDecryptionKeyResolver(decryptJwks))
                .build();
        JwtClaims jwtClaims = decryptConsumer.processToClaims(claims.getSubject());
        jwtClaims.getClaimsMap().forEach(claims::setClaim);
      }
      return claims;
    } catch (InvalidJwtException | MalformedClaimException e) {
      throw new TokenException("invalid_access_token", e);
    }
  }

  public void parse(JwtClaims claims, AccessToken token) {
    try {
      super.parse(claims, token);
      String scopes = claims.getStringClaimValue(SCOPE);
      if (StringUtils.isNotBlank(scopes)) {
        token.setScope(Splitter.on(StringUtils.SPACE).trimResults().splitToList(scopes));
      }
    } catch (MalformedClaimException e) {
      throw new TokenException("token_parse_failed", e);
    }
  }
}
