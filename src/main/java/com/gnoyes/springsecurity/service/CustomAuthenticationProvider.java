package com.gnoyes.springsecurity.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;

@Slf4j
@RequiredArgsConstructor
@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final AuthenticationService authenticationService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();

        UserDetails user = authenticationService.loadUserByUsername(username);

        Collection<GrantedAuthority> authorities = new ArrayList<>(user.getAuthorities());

        if (!matchPassword(password, user.getPassword())) {
            log.debug("matchPassword :::::::: false!");
            throw new BadCredentialsException(username);
        }

        if (!user.isEnabled()) {
            log.debug("isEnabled :::::::: false!");
            throw new BadCredentialsException(username);
        }

        log.debug("matchPassword :::::::: true!");

        return new UsernamePasswordAuthenticationToken(username, password, authorities);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return false;
    }

    private boolean matchPassword(String loginPwd, String password) {
        log.debug("matchPassword :::::::: check!");
        return loginPwd.equals(password);
    }
}
