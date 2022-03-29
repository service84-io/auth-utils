/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.service84.library.authutils.services;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service("EC235EB7-FA8E-4AE7-BA64-9347BAF0B1D2")
public class RSAKeyDecoder {
  private static final Logger logger = LoggerFactory.getLogger(RSAKeyDecoder.class);

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
    logger.debug("decodePublicKey");
    BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(base64Modulus));
    BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(base64Exponent));
    return (RSAPublicKey) keyFactory.generatePublic(new RSAPublicKeySpec(modulus, exponent));
  }
}
