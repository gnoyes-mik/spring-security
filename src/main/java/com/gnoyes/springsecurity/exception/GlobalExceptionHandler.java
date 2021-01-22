package com.gnoyes.springsecurity.exception;

import com.gnoyes.springsecurity.enums.ErrorCode;
import com.gnoyes.springsecurity.exception.custom.AuthenticationDeniedException;
import com.gnoyes.springsecurity.exception.custom.CustomJwtRuntimeException;
import com.gnoyes.springsecurity.exception.custom.DuplicateAccountException;
import com.gnoyes.springsecurity.model.errorResponse.ErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import javax.security.auth.login.LoginException;
import java.nio.file.AccessDeniedException;

@Slf4j
@ControllerAdvice
public class GlobalExceptionHandler {

    /**
     * 지원하지 않은 HTTP method 호출 할 경우 발생
     */
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ErrorResponse> handleHttpRequestMethodNotSupportedException(HttpRequestMethodNotSupportedException e) {
        log.error("handleHttpRequestMethodNotSupportedException", e);
        final ErrorResponse response = ErrorResponse.of(ErrorCode.METHOD_NOT_ALLOWED);
        return new ResponseEntity<>(response, HttpStatus.METHOD_NOT_ALLOWED);
    }

    /**
     * 잘못된 method argument로 호출 할 경우 발생
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleMethodArgumentNotValidException(MethodArgumentNotValidException e){
        log.error("handleMethodArgumentNotValidException", e);
        final ErrorResponse response = ErrorResponse.of(ErrorCode.INVALID_INPUT_VALUE);
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    /**
     * Authentication 객체가 필요한 권한을 보유하지 않은 경우 발생합
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDeniedException(AccessDeniedException e) {
        log.error("handleAccessDeniedException", e);
        final ErrorResponse response = ErrorResponse.of(ErrorCode.HANDLE_ACCESS_DENIED);
        return new ResponseEntity<>(response, HttpStatus.valueOf(ErrorCode.HANDLE_ACCESS_DENIED.getStatus()));
    }

    /**
     * 존재하지 않는 Username으로 조회 할 경우 발생
     */
    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleUsernameNotFoundException(UsernameNotFoundException e){
        log.error("handleUsernameNotFoundException", e);
        final ErrorResponse response = ErrorResponse.of(ErrorCode.USER_NOT_FOUND);
        return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
    }

    /**
     * 중복된 Username으로 회원 가입 할 경우 발생
     */
    @ExceptionHandler(DuplicateAccountException.class)
    public ResponseEntity<ErrorResponse> handleDuplicateAccountException(DuplicateAccountException e){
        log.error("handleDuplicateAccountException", e);
        final ErrorResponse response = ErrorResponse.of(ErrorCode.USER_NAME_DUPLICATION);
        return new ResponseEntity<>(response, HttpStatus.valueOf(ErrorCode.USER_NAME_DUPLICATION.getStatus()));
    }

    /**
     * Login 실패 시 발상
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleLoginException(BadCredentialsException e){
        log.error("BadCredentialsException", e);
        final ErrorResponse response = ErrorResponse.of(ErrorCode.USER_LOGIN_FAIL);
        return new ResponseEntity<>(response, HttpStatus.valueOf(ErrorCode.USER_LOGIN_FAIL.getStatus()));
    }

    /**
     * jwt 토큰이 만료되었거나 권한에 맞지 않는 토큰일 경우 발생
     */
    @ExceptionHandler(AuthenticationDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAuthenticationDeniedException(AuthenticationDeniedException e){
        log.error("handleAuthenticationDeniedException", e);
        final ErrorResponse response = ErrorResponse.of(ErrorCode.INVALID_JWT_TOKEN);
        return new ResponseEntity<>(response, HttpStatus.valueOf(ErrorCode.INVALID_JWT_TOKEN.getStatus()));
    }
    /**
     * 유효하지 않거나 잘못된 jwt 토큰일 경우 발생
     */
    @ExceptionHandler(CustomJwtRuntimeException.class)
    public ResponseEntity<ErrorResponse> handleCustomJwtRuntimeException(CustomJwtRuntimeException e){
        log.error("handleCustomJwtRuntimeException", e);
        final ErrorResponse response = ErrorResponse.of(ErrorCode.AUTHENTICATION_FAILED);
        return new ResponseEntity<>(response, HttpStatus.valueOf(ErrorCode.AUTHENTICATION_FAILED.getStatus()));
    }


    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleException(Exception e){
        log.error("handleException", e);
        final ErrorResponse response = ErrorResponse.of(ErrorCode.INTERNAL_SERVER_ERROR);
        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
