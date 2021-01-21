package com.gnoyes.springsecurity.exception.custom;

import com.gnoyes.springsecurity.enums.ErrorCode;

public class CustomJwtRuntimeException extends RuntimeException {

    private static final long serialVersionUID= -5607975382121189197L;

    public CustomJwtRuntimeException() {
        super(ErrorCode.AUTHENTICATION_FAILED.getMessage());
    }
}
