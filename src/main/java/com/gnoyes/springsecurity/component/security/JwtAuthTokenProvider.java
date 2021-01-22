package com.gnoyes.springsecurity.component.security;

import com.gnoyes.springsecurity.exception.custom.TokenValidFailedException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;


public class JwtAuthTokenProvider {

    private final Key key;
    private static final String AUTHORITIES_KEY = "role";

    public JwtAuthTokenProvider(String secret) {
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < 3; i++) sb.append(secret);

        this.key = Keys.hmacShaKeyFor(sb.toString().getBytes());
    }

    public JwtAuthToken createAuthToken(String id, String role, Date expiredDate) {
        return new JwtAuthToken(id, role, expiredDate, key);
    }

    public JwtAuthToken convertAuthToken(String token) {
        return new JwtAuthToken(token, key);
    }

    public Authentication getAuthentication(JwtAuthToken jwtAuthToken) {
        if (jwtAuthToken.validate()) {
            Claims claims = jwtAuthToken.getData();

            Collection<? extends GrantedAuthority> authorities =
                    Arrays.stream(new String[]{claims.get(AUTHORITIES_KEY).toString()})
                            .map(SimpleGrantedAuthority::new)
                            .collect(Collectors.toList());

            User principal = new User(claims.getSubject(), "", authorities);
            return new UsernamePasswordAuthenticationToken(principal, jwtAuthToken, authorities);
        } else {
            throw new TokenValidFailedException();
        }
    }
}
