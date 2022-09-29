package com.donphds.common.auth;

import java.util.List;

public interface Audience {

  String getId();

  List<String> getAudiences();

  String getSignSecret();

  List<String> getVerifySecrets();

  List<String> getDecryptSecrets();

  String getEncryptSecrets();
}
