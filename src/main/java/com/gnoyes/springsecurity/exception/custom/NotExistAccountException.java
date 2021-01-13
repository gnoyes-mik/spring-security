package com.gnoyes.springsecurity.exception.custom;

public class NotExistAccountException extends Exception{
    private static final long serialVersionUID = 1322386629204967082L;

    public NotExistAccountException(String message){
        super(message);
    }
}
