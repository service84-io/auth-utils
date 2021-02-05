package io.service84.library.authutils.services;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service("E0940F39-24CA-4034-BA65-23E1BB8317B3")
public class AuthenticationService {
  public Authentication getAuthentication() {
    SecurityContext context = SecurityContextHolder.getContext();

    if (context == null) {
      return null;
    }

    return context.getAuthentication();
  }

  public String getAuthenticationToken() {
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
    return getScopes();
  }

  public List<String> getScopes() {
    Authentication authentication = getAuthentication();

    if (authentication == null) {
      return Collections.emptyList();
    }

    Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

    if (authorities == null) {
      return Collections.emptyList();
    }

    return authorities
        .stream()
        .filter(a -> a != null)
        .map(a -> a.getAuthority())
        .collect(Collectors.toList());
  }

  public String getSubject() {
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
    SecurityContext context = SecurityContextHolder.getContext();

    if (context != null) {
      context.setAuthentication(authentication);
    }
  }
}
