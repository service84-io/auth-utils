package io.service84.library.authutils.services;

import java.util.Base64;

import org.apache.commons.lang3.ObjectUtils;
import org.springframework.stereotype.Service;

@Service("E82DC8B4-EBBF-4805-A569-EB61AFF6A080")
public class BasicAuthenticationXCoder {
  public static class BasicAuthentication {
    public String identifier;
    public String secret;
  }

  private static String BasicPrefix = "Basic ";

  public BasicAuthentication decode(String encodedBearerAuthentication) {
    if (encodedBearerAuthentication == null) {
      return null;
    }

    String encodedAuthentication = encodedBearerAuthentication.replaceFirst(BasicPrefix, "");

    try {
      String formattedAuthentication =
          new String(Base64.getUrlDecoder().decode(encodedAuthentication));
      String[] authenticationParts = formattedAuthentication.split(":", 2);
      BasicAuthentication authentication = new BasicAuthentication();
      authentication.identifier = authenticationParts[0];

      if (authenticationParts.length == 2) {
        authentication.secret = authenticationParts[1];
      } else {
        authentication.secret = "";
      }

      return authentication;
    } catch (IllegalArgumentException e) {
      return null;
    }
  }

  public String encode(BasicAuthentication authentication) {
    if (authentication == null) {
      return null;
    }

    String identifier = ObjectUtils.firstNonNull(authentication.identifier, "");
    String secret = ObjectUtils.firstNonNull(authentication.secret, "");
    String formattedAuthentication = identifier + ":" + secret;
    String encodedAuthentication =
        Base64.getUrlEncoder().encodeToString(formattedAuthentication.getBytes());
    return BasicPrefix + encodedAuthentication;
  }
}
