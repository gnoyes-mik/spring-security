package com.gnoyes.springsecurity.exception.custom;

import com.gnoyes.springsecurity.enums.ErrorCode;

public class TokenValidFailedException extends RuntimeException {

    public TokenValidFailedException(){
        super(ErrorCode.TOKEN_GENERATION_FAILED.getMessage());
    }

    private TokenValidFailedException(String msg){
        super(msg);
    }
}