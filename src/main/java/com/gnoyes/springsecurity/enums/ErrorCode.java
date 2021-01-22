package com.gnoyes.springsecurity.enums;

import lombok.Getter;

@Getter
public enum ErrorCode {
    // Common
    INVALID_INPUT_VALUE(400, "C001", " Invalid Input Value"),
    METHOD_NOT_ALLOWED(405, "C002", " Invalid HTTP Method"),
    HANDLE_ACCESS_DENIED(403, "C003", "Access is Denied"),
    INTERNAL_SERVER_ERROR(500, "C004", "Internal Server Error"),

    // Account(User)
    USER_NAME_DUPLICATION(400, "A001", "Username is already exist"),
    USER_NOT_FOUND(404, "A002", "User Not Found"),
    USER_LOGIN_FAIL(400, "A403", "Check user name and password"),
    INVALID_JWT_TOKEN(401, "404", "Invalid JWT token"),
    AUTHENTICATION_FAILED(403, "A005", "Authentication failed"),
    TOKEN_GENERATION_FAILED(500, "A006", "Token generation failed"),
    ;

    private final int status;
    private final String code;
    private final String message;

    ErrorCode(final int status, final String code, final String message) {
        this.status = status;
        this.code = code;
        this.message = message;
    }
}
