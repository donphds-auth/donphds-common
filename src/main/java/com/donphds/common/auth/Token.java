package com.donphds.common.auth;

import lombok.Data;

@Data
public abstract class Token {
  private String aud;
  private String sub;
  private long expireAt;
  private long iat;
}
