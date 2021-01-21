package com.gnoyes.springsecurity.exception.custom;

import com.gnoyes.springsecurity.enums.ErrorCode;

public class AuthenticationDeniedException extends RuntimeException{

    public AuthenticationDeniedException(){
        super(ErrorCode.INVALID_JWT_TOKEN.getMessage());
    }

}
