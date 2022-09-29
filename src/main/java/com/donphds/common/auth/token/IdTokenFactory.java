package com.donphds.common.auth.token;

import com.donphds.common.auth.Issuer;
import com.donphds.common.exception.TokenException;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;

public class IdTokenFactory extends TokenFactory<IdToken> {

  protected static final String NICKNAME = "nickname";
  protected static final String PICTURE = "picture";
  protected static final String NONCE = "nonce";

  public IdTokenFactory(Issuer issuer) {
    super(issuer);
  }

  public void parse(JwtClaims claims, IdToken token) {
    super.parse(claims, token);
    token.setNickname(claims.getClaimValueAsString(NICKNAME));
    token.setPicture(claims.getClaimValueAsString(PICTURE));
    token.setNonce(claims.getClaimValueAsString(NONCE));
    try {
      token.setSub(claims.getSubject());
    } catch (MalformedClaimException e) {
      throw new TokenException("invalid_id_token", e);
    }
  }
}
