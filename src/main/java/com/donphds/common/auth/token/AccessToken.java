package com.donphds.common.auth.token;

import java.util.List;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = false)
public class AccessToken extends IdToken {
  private List<String> scope;
}
