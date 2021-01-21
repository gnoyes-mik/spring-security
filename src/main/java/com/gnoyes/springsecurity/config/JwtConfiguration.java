package com.gnoyes.springsecurity.config;

import com.gnoyes.springsecurity.component.security.JwtAuthTokenProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtConfiguration {

    @Value("$jwt.secret")
    private String secret;

    @Bean
    public JwtAuthTokenProvider JwtProvider(){
        return new JwtAuthTokenProvider(secret);
    }
}
