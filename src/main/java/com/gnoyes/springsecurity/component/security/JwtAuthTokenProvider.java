package com.gnoyes.springsecurity.component.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.SignatureAlgorithm;

import java.security.Key;
import java.util.Date;


public class JwtAuthTokenProvider {

    private final Key key;

    public JwtAuthTokenProvider(String secret) {
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < 5; i++) sb.append(secret);

        this.key = Keys.hmacShaKeyFor(sb.toString().getBytes());
    }

    public JwtAuthToken createAuthToken(String id, String role, Date expiredDate) {
        return new JwtAuthToken(id, role, expiredDate, key);
    }

    public JwtAuthToken convertAuthToken(String token) {
        return new JwtAuthToken(token, key);
    }

}
