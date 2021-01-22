package com.gnoyes.springsecurity.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gnoyes.springsecurity.enums.ErrorCode;
import com.gnoyes.springsecurity.model.errorResponse.ErrorResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException {

        ObjectMapper objectMapper = new ObjectMapper();
        ErrorResponse errorResponse = ErrorResponse.builder()
                .code(ErrorCode.AUTHENTICATION_DENIED.getCode())
                .status(ErrorCode.AUTHENTICATION_DENIED.getStatus())
                .message(ErrorCode.AUTHENTICATION_DENIED.getMessage())
                .build();
        response.getOutputStream().println(objectMapper.writeValueAsString(errorResponse));
    }
}