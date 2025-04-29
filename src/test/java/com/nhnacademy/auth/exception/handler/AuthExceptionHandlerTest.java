package com.nhnacademy.auth.exception.handler;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;

@WebMvcTest(AuthExceptionHandler.class)
@ExtendWith(MockitoExtension.class)
class AuthExceptionHandlerTest {

    @Test
    @DisplayName("로그인 시도 실패 시 설정한 ErrorResponse 반환 체크 ")
    void attemptAuthenticationException() {

    }

    @Test
    @DisplayName("JwtTokenDto generateTokenDto 시 String userEmail, roll가 null일 때 ")
    void tokenDtoGenerateFailedException() {
    }

    @Test
    @DisplayName("getUserEmailFromToken 에서 accessToken이 Empty일 때")
    void tokenMissingException_1() {
    }


    @Test
    @DisplayName("getRoleIdFromToken에서 token이 empty일 때")
    void tokenMissingException_2() {
    }

    @Test
    void tokenNotFoundFromCookieException() {
    }

    @Test
    void userNameNotFoundException() {
    }
}