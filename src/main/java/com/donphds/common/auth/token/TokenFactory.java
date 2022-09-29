package com.donphds.common.auth.token;

import cn.hutool.core.collection.CollectionUtil;
import com.donphds.common.auth.Audience;
import com.donphds.common.auth.Issuer;
import com.donphds.common.auth.Token;
import com.donphds.common.exception.KeyException;
import com.donphds.common.exception.TokenException;
import com.google.common.collect.Lists;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;
import org.jose4j.base64url.Base64Url;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;
import org.jose4j.lang.InvalidAlgorithmException;
import org.jose4j.lang.JoseException;

@AllArgsConstructor
public abstract class TokenFactory<T extends Token> {
  protected static final String AUD = "aud";
  protected static final String SUB = "sub";
  protected static final String NBF = "nbf";
  protected static final String EXP = "exp";
  protected static final String IAT = "iat";

  @Setter private Issuer issuer;

  public JwtClaims generate(T token, Audience audience) throws JoseException {
    JwtClaims jwtClaims = new JwtClaims();
    jwtClaims.setGeneratedJwtId();
    if (token.getIat() == 0L) {
      jwtClaims.setIssuedAtToNow();
    } else {
      jwtClaims.setIssuedAt(NumericDate.fromSeconds(token.getIat()));
    }
    if (token.getExpireAt() != 0L) {
      jwtClaims.setExpirationTime(NumericDate.fromSeconds(token.getExpireAt()));
    }
    jwtClaims.setSubject(token.getSub());
    jwtClaims.setIssuer(this.issuer.getIss());
    jwtClaims.setNotBeforeMinutesInThePast(0.0F);
    if (CollectionUtil.isNotEmpty(audience.getAudiences())) {
      jwtClaims.setAudience(audience.getAudiences());
    }
    return jwtClaims;
  }

  protected String sign(JwtClaims claims, Supplier<String> signKey) throws JoseException {
    if (Objects.isNull(signKey) || StringUtils.isBlank(signKey.get())) {
      throw new InvalidAlgorithmException("invalid_sign_key");
    }
    JsonWebSignature signature = new JsonWebSignature();
    String signKeyStr = Base64Url.decodeToString(signKey.get(), StandardCharsets.UTF_8.toString());
    JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk(signKeyStr);
    if (jsonWebKey instanceof PublicJsonWebKey) {
      PublicJsonWebKey publicJsonWebKey = (PublicJsonWebKey) jsonWebKey;
      signature.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
      signature.setKeyIdHeaderValue(publicJsonWebKey.getKeyId());
      signature.setKey(publicJsonWebKey.getPrivateKey());
    }
    signature.setPayload(claims.toJson());
    return signature.getCompactSerialization();
  }

  public JwtClaims verify(String token, Audience audience) {
    try {
      List<String> verifyKeys =
          Optional.ofNullable(audience.getVerifySecrets()).orElse(new ArrayList<>());
      List<JsonWebKey> verifyJwks = this.buildJwks(verifyKeys);
      JwtConsumer verifyConsumer =
          this.consumerBuilder()
              .setExpectedIssuer(issuer.getIss())
              .setExpectedAudience(audience.getAudiences().toArray(String[]::new))
              .setVerificationKeyResolver(
                  new JwksVerificationKeyResolver(Lists.newArrayList(verifyJwks)))
              .build();
      return verifyConsumer.processToClaims(token);
    } catch (InvalidJwtException e) {
      throw new TokenException("invalid_token", e);
    }
  }

  protected JwtConsumerBuilder consumerBuilder() {
    return new JwtConsumerBuilder()
        .setRequireJwtId()
        .setRequireSubject()
        .setRequireIssuedAt()
        .setExpectedAudience("")
        .setExpectedIssuer("")
        .setRequireNotBefore()
        .setAllowedClockSkewInSeconds(30);
  }

  protected List<JsonWebKey> buildJwks(List<String> keys) {
    return keys.stream()
        .map(
            key -> {
              try {
                return JsonWebKey.Factory.newJwk(Base64Url.decodeToUtf8String(key));
              } catch (JoseException e) {
                throw new KeyException("invalid_key_to_jwk", e);
              }
            })
        .collect(Collectors.toList());
  }

  public void parse(JwtClaims claims, T token) {
    try {
      token.setSub(claims.getClaimValueAsString(SUB));
      token.setAud(String.join(StringUtils.SPACE, claims.getStringListClaimValue(AUD)));
      ;
      token.setIat(claims.getIssuedAt().getValue());
      token.setExpireAt(claims.getExpirationTime().getValue());
    } catch (MalformedClaimException e) {
      throw new TokenException("token parse failed", e);
    }
  }
}
