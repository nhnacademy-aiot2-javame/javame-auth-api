package com.nhnacademy.auth.exception;

public class MissingTokenException extends RuntimeException {
    public MissingTokenException(String token) {
        super(String.format("%s is missing from the request.", token));
    }
}
