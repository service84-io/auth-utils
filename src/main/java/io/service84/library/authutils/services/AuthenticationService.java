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

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service("E0940F39-24CA-4034-BA65-23E1BB8317B3")
public class AuthenticationService {
  private static final Logger logger = LoggerFactory.getLogger(AuthenticationService.class);

  public Authentication getAuthentication() {
    logger.debug("getAuthentication");
    SecurityContext context = SecurityContextHolder.getContext();

    if (context == null) {
      return null;
    }

    return context.getAuthentication();
  }

  public String getAuthenticationToken() {
    logger.debug("getAuthenticationToken");
    Authentication authentication = getAuthentication();

    if (authentication == null) {
      return null;
    }

    Object credentials = authentication.getCredentials();

    if (credentials == null) {
      return null;
    }

    return credentials.toString();
  }

  public List<String> getPermissions() {
    logger.debug("getPermissions");
    return getScopes();
  }

  public List<String> getScopes() {
    logger.debug("getScopes");
    Authentication authentication = getAuthentication();

    if (authentication == null) {
      return Collections.emptyList();
    }

    Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

    if (authorities == null) {
      return Collections.emptyList();
    }

    return authorities.stream()
        .filter(a -> a != null)
        .map(a -> a.getAuthority())
        .collect(Collectors.toList());
  }

  public String getSubject() {
    logger.debug("getSubject");
    Authentication authentication = getAuthentication();

    if (authentication == null) {
      return null;
    }

    Object principal = authentication.getPrincipal();

    if (principal == null) {
      return null;
    }

    return principal.toString();
  }

  public void setAuthentication(Authentication authentication) {
    logger.debug("setAuthentication");
    SecurityContext context = SecurityContextHolder.getContext();

    if (context != null) {
      context.setAuthentication(authentication);
    }
  }
}
