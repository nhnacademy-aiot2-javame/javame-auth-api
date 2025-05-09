package com.nhnacademy.auth.exception;

public class GenerateTokenDtoException extends RuntimeException {
    public GenerateTokenDtoException(String tokenDto) {
        super(String.format("%s is empty.", tokenDto));
    }
}
