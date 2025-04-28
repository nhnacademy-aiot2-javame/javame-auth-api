package com.nhnacademy.auth.exception;

public class GenerateTokenDtoException extends RuntimeException {
    public GenerateTokenDtoException(String message) {
        super(String.format("%s is empty.", message));
    }
}
