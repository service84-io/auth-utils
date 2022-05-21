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
