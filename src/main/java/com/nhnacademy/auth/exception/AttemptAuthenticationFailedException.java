package com.nhnacademy.auth.exception;

import org.springframework.security.core.AuthenticationException;

public class AttemptAuthenticationFailedException extends AuthenticationException {
    /**
     * 특별한 문자를 추가하지 않을 때 넣어주는 디폴트 에러 메시지.
     */
    private static final String DEFAULT_ERROR_MESSAGE = "Username and Password not accepted";


    public AttemptAuthenticationFailedException(String message) {
        super(message);
    }

    public AttemptAuthenticationFailedException() {
        super(DEFAULT_ERROR_MESSAGE);
    }
}
