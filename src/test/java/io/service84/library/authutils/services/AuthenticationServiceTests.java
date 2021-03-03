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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@SuppressWarnings("serial")
@ExtendWith(SpringExtension.class)
public class AuthenticationServiceTests {
  @TestConfiguration
  public static class Configuration {

    @Bean
    public AuthenticationService getAuthenticationService() {
      return new AuthenticationService();
    }
  }

  // Test Subject
  @Autowired private AuthenticationService authenticationService;

  @Test
  public void authCredentialsIsTokenTest() {
    UUID credentials = UUID.randomUUID();
    Authentication authentication = mock(Authentication.class);
    when(authentication.getCredentials()).thenReturn(credentials);
    authenticationService.setAuthentication(authentication);
    String token = authenticationService.getAuthenticationToken();
    assertEquals(credentials.toString(), token);
  }

  @Test
  public void authority2Mapped() {
    String authorityValue1 = UUID.randomUUID().toString();
    String authorityValue2 = UUID.randomUUID().toString();
    GrantedAuthority authority1 = mock(GrantedAuthority.class);
    GrantedAuthority authority2 = mock(GrantedAuthority.class);
    when(authority1.getAuthority()).thenReturn(authorityValue1);
    when(authority2.getAuthority()).thenReturn(authorityValue2);
    List<GrantedAuthority> authorities = new ArrayList<>();
    authorities.add(authority1);
    authorities.add(authority2);
    Authentication authentication = getNonMockAuthenticationWithAuthorities(authorities);
    authenticationService.setAuthentication(authentication);
    List<String> scopes = authenticationService.getScopes();
    assertEquals(2, scopes.size());
    assertTrue(scopes.contains(authorityValue1));
    assertTrue(scopes.contains(authorityValue2));
  }

  @Test
  public void authorityMapped() {
    String authorityValue = UUID.randomUUID().toString();
    GrantedAuthority authority = mock(GrantedAuthority.class);
    when(authority.getAuthority()).thenReturn(authorityValue);
    List<GrantedAuthority> authorities = Collections.singletonList(authority);
    Authentication authentication = getNonMockAuthenticationWithAuthorities(authorities);
    authenticationService.setAuthentication(authentication);
    List<String> scopes = authenticationService.getScopes();
    assertEquals(1, scopes.size());
    assertTrue(scopes.contains(authorityValue));
  }

  @Test
  public void authPrincipalIsSubjectTest() {
    String principal = UUID.randomUUID().toString();
    Authentication authentication = mock(Authentication.class);
    when(authentication.getPrincipal()).thenReturn(principal);
    authenticationService.setAuthentication(authentication);
    String subject = authenticationService.getSubject();
    assertEquals(principal, subject);
  }

  @Test
  public void getAuthenticationTest() {
    Authentication authentication = mock(Authentication.class);
    authenticationService.setAuthentication(authentication);
    Authentication gotAuthentication = authenticationService.getAuthentication();
    assertEquals(authentication, gotAuthentication);
  }

  private Authentication getNonMockAuthenticationWithAuthorities(
      Collection<? extends GrantedAuthority> authorities) {
    return new AbstractAuthenticationToken(authorities) {

      @Override
      public Object getCredentials() {
        return null;
      }

      @Override
      public Object getPrincipal() {
        return null;
      }
    };
  }

  @Test
  public void nullAuthEmptyScopesTest() {
    authenticationService.setAuthentication(null);
    List<String> scopes = authenticationService.getScopes();
    assertTrue(scopes.isEmpty());
  }

  @Test
  public void nullAuthNullSubjectTest() {
    authenticationService.setAuthentication(null);
    String subject = authenticationService.getSubject();
    assertEquals(null, subject);
  }

  @Test
  public void setAuthenticationTest() {
    Authentication authentication = mock(Authentication.class);
    authenticationService.setAuthentication(authentication);
  }
}
