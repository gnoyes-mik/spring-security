package com.gnoyes.springsecurity.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gnoyes.springsecurity.enums.ErrorCode;
import com.gnoyes.springsecurity.model.errorResponse.ErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {

        final String exception = (String) request.getAttribute("exception");

        log.error("[JwtAuthenticationEntryPoint] " + exception);

        if (ErrorCode.INVALID_JWT_SIGNATURE.getCode().equals(exception)) {
            setResponse(response, ErrorCode.INVALID_JWT_SIGNATURE);
        } else if (ErrorCode.INVALID_JWT_TOKEN.getCode().equals(exception)) {
            setResponse(response, ErrorCode.INVALID_JWT_TOKEN);
        } else if (ErrorCode.EXPIRED_JWT_TOKEN.getCode().equals(exception)) {
            setResponse(response, ErrorCode.EXPIRED_JWT_TOKEN);
        } else if (ErrorCode.UNSUPPORTED_JWT_TOKEN.getCode().equals(exception)) {
            setResponse(response, ErrorCode.UNSUPPORTED_JWT_TOKEN);
        } else if (ErrorCode.ILLEGAL_ARGUMENT.getCode().equals(exception)) {
            setResponse(response, ErrorCode.ILLEGAL_ARGUMENT);
        } else {
            setResponse(response, ErrorCode.AUTHENTICATION_FAILED);
        }


    }

    private void setResponse(HttpServletResponse response, ErrorCode errorCode) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        ErrorResponse errorResponse = ErrorResponse.builder()
                .code(errorCode.getCode())
                .status(errorCode.getStatus())
                .message(errorCode.getMessage())
                .build();

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().println(objectMapper.writeValueAsString(errorResponse));
    }
}