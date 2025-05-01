package com.nhnacademy.auth.exception.controller;

import com.nhnacademy.auth.exception.AttemptAuthenticationFailedException;
import com.nhnacademy.auth.exception.GenerateTokenDtoException;
import com.nhnacademy.auth.exception.MissingTokenException;
import com.nhnacademy.auth.exception.TokenNotFoundFromCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class ExceptionTestController {

    /**
     *  Exception에 넣어줄 테스트용 토큰.
     */
    private final String exceptionToken = "test";

    @GetMapping("/login-failed")
    public ResponseEntity<String> loginFailed() {
        throw new AttemptAuthenticationFailedException();
    }

    @GetMapping("/login-failed/message")
    public ResponseEntity<String> loginFailedMessage() {
        throw new AttemptAuthenticationFailedException("message");
    }

    @GetMapping("/token-failed")
    public void tokenGeneratedFailed() {
        throw new GenerateTokenDtoException(exceptionToken);
    }

    @GetMapping("/token-missing")
    public void tokenMissing() {
        throw new MissingTokenException(exceptionToken);
    }

    @GetMapping("/token-not-found")
    public void tokenNotFoundFromCookie() {
        throw new TokenNotFoundFromCookie();
    }

    @GetMapping("/token-not-found/message")
    public void tokenNotFoundFromCookieByMessage() {
        throw new TokenNotFoundFromCookie("message");
    }

    @GetMapping("/auth-failed")
    public void authFailed() {
        throw new UsernameNotFoundException("test-auth");
    }
}
