package com.gnoyes.springsecurity.exception.custom;

public class DuplicateAccountException extends Exception {

private static final long serialVersionUID = 1431688116258338909L;

    public DuplicateAccountException(String message) {
        super(message);
    }
}
