package io.service84.library.authutils.services;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import io.service84.library.authutils.services.BasicAuthenticationXCoder.BasicAuthentication;

@ExtendWith(SpringExtension.class)
public class BasicAuthenticationXCoderTests {
  @TestConfiguration
  public static class Configuration {

    @Bean
    public BasicAuthenticationXCoder getBasicAuthenticationXCoder() {
      return new BasicAuthenticationXCoder();
    }
  }

  // Test Subject
  @Autowired BasicAuthenticationXCoder xcoder;

  @Test
  public void nullDecodeTest() {
    BasicAuthentication encodedNull = xcoder.decode(null);
    assertEquals(null, encodedNull);
  }

  @Test
  public void nullEncodeTest() {
    String encodedNull = xcoder.encode(null);
    assertEquals(null, encodedNull);
  }

  @Test
  public void translateEqualTest() {
    BasicAuthentication authentication = new BasicAuthentication();
    authentication.identifier = UUID.randomUUID().toString();
    authentication.secret = UUID.randomUUID().toString();
    String authenticationString = xcoder.encode(authentication);
    BasicAuthentication translatedAuthentication = xcoder.decode(authenticationString);
    assertEquals(authentication.identifier, translatedAuthentication.identifier);
    assertEquals(authentication.secret, translatedAuthentication.secret);
  }

  @Test
  public void translateNullToEmptyStringTest() {
    BasicAuthentication authentication = new BasicAuthentication();
    authentication.identifier = null;
    authentication.secret = null;
    String authenticationString = xcoder.encode(authentication);
    BasicAuthentication translatedAuthentication = xcoder.decode(authenticationString);
    assertEquals("", translatedAuthentication.identifier);
    assertEquals("", translatedAuthentication.secret);
  }
}
