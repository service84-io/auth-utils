package io.service84.library.authutils.services;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import org.springframework.stereotype.Service;

@Service("EC235EB7-FA8E-4AE7-BA64-9347BAF0B1D2")
public class RSAKeyDecoder {
  private KeyFactory keyFactory;

  public RSAKeyDecoder() {
    try {
      keyFactory = KeyFactory.getInstance("RSA");
    } catch (NoSuchAlgorithmException e) {
      throw new Error(
          "The Presumed Impossible NoSuchAlgorithmException was encountered while getting the RSA Key Factory");
    }
  }

  public RSAPublicKey decodePublicKey(String base64Modulus, String base64Exponent)
      throws InvalidKeySpecException {
    BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(base64Modulus));
    BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(base64Exponent));
    return (RSAPublicKey) keyFactory.generatePublic(new RSAPublicKeySpec(modulus, exponent));
  }
}
