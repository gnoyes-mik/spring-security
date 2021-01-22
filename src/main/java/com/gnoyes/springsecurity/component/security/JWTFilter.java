package com.gnoyes.springsecurity.component.security;

import com.gnoyes.springsecurity.enums.ErrorCode;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;

@Slf4j
public class JWTFilter extends GenericFilterBean {

    private static final String AUTHORIZATION_HEADER = "x-auth-token";
    private static final String AUTHORITIES_KEY = "role";

    private JwtAuthTokenProvider jwtAuthTokenProvider;

    JWTFilter(JwtAuthTokenProvider jwtAuthTokenProvider) {
        this.jwtAuthTokenProvider = jwtAuthTokenProvider;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        String token = request.getHeader(AUTHORIZATION_HEADER);

        if (token != null) {
            JwtAuthToken jwtAuthToken = jwtAuthTokenProvider.convertAuthToken(token);

            Claims claims = null;

            try {
                claims = Jwts.parserBuilder().setSigningKey(jwtAuthTokenProvider.getKey()).build().parseClaimsJws(token).getBody();
            } catch (SecurityException e) {
                log.info("Invalid JWT signature.");
                request.setAttribute("exception", ErrorCode.INVALID_JWT_SIGNATURE.getCode());
            } catch (MalformedJwtException e) {
                log.info("Invalid JWT token.");
                request.setAttribute("exception", ErrorCode.INVALID_JWT_TOKEN.getCode());
            } catch (ExpiredJwtException e) {
                log.info("Expired JWT token.");
                request.setAttribute("exception", ErrorCode.EXPIRED_JWT_TOKEN.getCode());
            } catch (UnsupportedJwtException e) {
                log.info("Unsupported JWT token.");
                request.setAttribute("exception", ErrorCode.UNSUPPORTED_JWT_TOKEN.getCode());
            } catch (IllegalArgumentException e) {
                log.info("JWT token compact of handler are invalid.");
                request.setAttribute("exception", ErrorCode.ILLEGAL_ARGUMENT.getCode());
            }

            if (claims != null) {
                Authentication authentication = getAuthentication(jwtAuthToken, claims);

                // 인증 성공시 SecurityContext에 Authentication 객체를 추가해줌
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }

    public Authentication getAuthentication(JwtAuthToken jwtAuthToken, Claims claims) {
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(new String[]{claims.get(AUTHORITIES_KEY).toString()})
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        User principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, jwtAuthToken, authorities);
    }

}