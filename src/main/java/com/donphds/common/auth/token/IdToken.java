package com.donphds.common.auth.token;

import com.donphds.common.auth.Token;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = false)
public class IdToken extends Token {
  private String nickname;
  private String picture;
  private String nonce;
}
