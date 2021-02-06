package io.service84.library.authutils.services;

import static org.junit.Assert.assertTrue;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
public class RSAKeyDecoderTests {
  @TestConfiguration
  public static class Configuration {

    @Bean
    public RSAKeyDecoder getRSAKeyDecoder() {
      return new RSAKeyDecoder();
    }
  }

  private static String AURLBase64Modulus =
      "gguAfSl1G4CkBV4ezHVtW6HfHS8hmX9zYfrD2DeYdLJ7leefwKaleCm-jUCzmp-sJHYml7rDsz832ZktTNd1gMt9q4Ohj6ANKubHQL4BEFkYF51lLr4zQs5Vu7vqHYEneoonrwRF1K9vIYOG1Ujkry_B-Pj9Tr8aGQu5AaHYoS8=";
  private static String AURLBase64Exponent = "AQAB";
  private static String AMessage = "A9D9B8D0-955B-4337-9C50-1A8611916B6C";
  private static String ABase64Signature =
      "bWkOWSGAQYQgrHZSq/ZSrXScu15qxKvUrttQGGCeuiYnUiYoMprHUPM5yhkDa45ZErrqbQl9u5jBgL8ZbV4vFcYz8g8f8xZi90L/AEwtszP9STi8IKgkWb9CpV+loNTEq/EvCwe6j4kOctELe2C+UUU/eX+W4g8hDEvYKYdMZvM=";

  @Autowired private RSAKeyDecoder rsaKeyDecoder;

  @Test(expected = InvalidKeySpecException.class)
  public void decodeInvalidKeyTest() throws InvalidKeySpecException {
    rsaKeyDecoder.decodePublicKey("INVALID", "INVALID");
  }

  @Test
  public void decodeKeyTest() throws InvalidKeySpecException {
    rsaKeyDecoder.decodePublicKey(AURLBase64Modulus, AURLBase64Exponent);
  }

  @Test
  public void verifyTest()
      throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException,
          InvalidKeyException, SignatureException {
    RSAPublicKey publicKey = rsaKeyDecoder.decodePublicKey(AURLBase64Modulus, AURLBase64Exponent);
    Signature signature = Signature.getInstance("SHA1withRSA");
    signature.initVerify(publicKey);
    signature.update(AMessage.getBytes());
    assertTrue(signature.verify(Base64.getDecoder().decode(ABase64Signature)));
  }
}
