package com.donphds.common.auth;

import cn.hutool.core.codec.Base62;
import com.donphds.common.auth.token.AccessToken;
import com.donphds.common.auth.token.AccessTokenFactory;
import com.google.common.collect.Lists;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import org.jose4j.base64url.Base64Url;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.OctJwkGenerator;
import org.jose4j.jwk.OctetSequenceJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.Test;

class TokenTest {

  @Test
  void testTokenFactory() throws JoseException {
    TestAudience testAudience = new TestAudience();
    AccessTokenFactory accessTokenFactory = new AccessTokenFactory(new TestIssuer());
    AccessToken accessToken = new AccessToken();
    accessToken.setNickname("nickname");
    accessToken.setPicture("picture");
    accessToken.setSub("openid");
    accessToken.setExpireAt(Instant.now().plusSeconds(30L).getEpochSecond());
    accessToken.setScope(Lists.newArrayList("read:pr:", "write:sdaa"));
    String token = accessTokenFactory.issue(accessToken, testAudience);
    System.err.println(token);

    JwtClaims verify = accessTokenFactory.verify(token, testAudience);
    verify
        .getClaimsMap()
        .forEach(
            (k, v) -> {
              System.err.printf("k: %s, v: %s%n", k, v);
            });
  }

  static class TestIssuer implements Issuer {
    @Override
    public String getIss() {
      return "issuer";
    }
  }

  static class TestAudience implements Audience {

    private String signSecret;
    private String encryptSecret;
    private List<String> verifySecrets;
    private List<String> decryptSecrets;

    private List<String> audiences;

    TestAudience() throws JoseException {
      RsaJsonWebKey rsaJsonWebKey = RsaJwkGenerator.generateJwk(2048);
      ThreadLocal<SecureRandom> secureRandomThreadLocal =
          ThreadLocal.withInitial(SecureRandom::new);
      rsaJsonWebKey.setKeyId("123");
      OctetSequenceJsonWebKey octetSequenceJsonWebKey =
          OctJwkGenerator.generateJwk(256, new SecureRandom());
      octetSequenceJsonWebKey.setKeyId("321");
      encryptSecret =
          Base64Url.encodeUtf8ByteRepresentation(
              octetSequenceJsonWebKey.toJson(JsonWebKey.OutputControlLevel.INCLUDE_SYMMETRIC));
      decryptSecrets =
          List.of(
              Base64Url.encodeUtf8ByteRepresentation(
                  octetSequenceJsonWebKey.toJson(JsonWebKey.OutputControlLevel.INCLUDE_SYMMETRIC)));
      signSecret =
          Base64Url.encodeUtf8ByteRepresentation(
              rsaJsonWebKey.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));
      verifySecrets =
          Lists.newArrayList(
              Base64Url.encodeUtf8ByteRepresentation(
                  rsaJsonWebKey.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)));
      byte[] bytes = new byte[16];
      secureRandomThreadLocal.get().nextBytes(bytes);
      audiences = Lists.newArrayList(Base62.encode(bytes));
    }

    @Override
    public String getId() {
      return "1";
    }

    @Override
    public List<String> getAudiences() {
      return audiences;
    }

    @Override
    public String getSignSecret() {
      return signSecret;
    }

    @Override
    public List<String> getVerifySecrets() {
      return verifySecrets;
    }

    @Override
    public List<String> getDecryptSecrets() {
      return decryptSecrets;
    }

    @Override
    public String getEncryptSecrets() {
      return encryptSecret;
    }
  }
}
