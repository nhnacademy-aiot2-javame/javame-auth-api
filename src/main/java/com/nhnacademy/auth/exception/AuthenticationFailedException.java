package com.nhnacademy.auth.exception;

public class AuthenticationFailedException extends RuntimeException{

    public AuthenticationFailedException(String e){
        super(e);
    }
}
