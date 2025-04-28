package com.nhnacademy.auth.exception.handler;

import com.nhnacademy.auth.exception.AuthenticationFailedException;
import com.nhnacademy.auth.exception.GenerateTokenDtoException;
import com.nhnacademy.auth.exception.MissingTokenException;
import com.nhnacademy.auth.exception.TokenNotFoundFromCookie;
import com.nhnacademy.auth.exception.dto.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;

/**
 * Application 전역에서 발생하는 예외를 처리하는 ControllerAdvice.
 */
@RestControllerAdvice
public class AuthExceptionHandler {

    /**
     * JwtAuthenticationFilter에서 로그인을 시도할 때 실패했을 경우 발생하는 예외입니다.
     *
     * @param ex AuthenticationFialedException
     * @return errorResponse
     */
    @ExceptionHandler(AuthenticationFailedException.class)
    public ResponseEntity<ErrorResponse> attemptAuthenticationException (AuthenticationFailedException ex) {
        HttpStatus status = HttpStatus.UNAUTHORIZED;

        ErrorResponse errorResponse = new ErrorResponse(
                LocalDateTime.now(),              // 에러 발생 시간
                status.value(),                   // 401
                status.getReasonPhrase(),         // "Unauthorized"
                ex.getMessage()                   // 예외에서 전달한 메시지
        );

        return new ResponseEntity<>(errorResponse, status);
    }

    /**
     * 토큰 생성에 필요한 role_id, member_email 값이 누락되거나 잘못 전송하여
     * 토큰이 생성되지 않았을 때 발생하는 예외입니다.
     *
     * @param ex GenerateTokenDtoException
     * @return errorResponse
     */
    @ExceptionHandler(GenerateTokenDtoException.class)
    public ResponseEntity<ErrorResponse> tokenDtoGenerateFailedException (GenerateTokenDtoException ex) {
        HttpStatus status = HttpStatus.BAD_REQUEST;

        ErrorResponse errorResponse = new ErrorResponse(
                LocalDateTime.now(),
                status.value(),
                status.getReasonPhrase(),
                ex.getMessage()
        );

        return new ResponseEntity<>(errorResponse, status);
    }

    /**
     * 인증이 필요한 요청을 했으나 accessToken이 없거나 유효하지 않을 때 발생하는 예외입니다.
     * @param ex
     * @return errorResponse
     */
    @ExceptionHandler(MissingTokenException.class)
    public ResponseEntity<ErrorResponse> tokenMissingException (MissingTokenException ex) {
        HttpStatus status = HttpStatus.UNAUTHORIZED;

        ErrorResponse errorResponse = new ErrorResponse(
                LocalDateTime.now(),
                status.value(),
                status.getReasonPhrase(),
                ex.getMessage()
        );

        return new ResponseEntity<>(errorResponse, status);
    }

    /**
     * request에서 token이 들어가 있는 쿠키를 찾을려 했으나 없거나 유효하지 않을 때 발생하는 예외입니다.
     *
     * @param ex TokenNotFoundFromCookie
     * @return errorResponse
     */
    @ExceptionHandler(TokenNotFoundFromCookie.class)
    public ResponseEntity<ErrorResponse> tokenNotFoundFromCookieException (TokenNotFoundFromCookie ex) {
        HttpStatus status = HttpStatus.BAD_REQUEST;

        ErrorResponse errorResponse = new ErrorResponse(
                LocalDateTime.now(),
                status.value(),
                status.getReasonPhrase(),
                ex.getMessage()
        );

        return new ResponseEntity<>(errorResponse, status);
    }

    /**
     * UserDetilasService에서 userName을 찾지 못했을 때 발생하는 예외입니다.
     *
     * @param ex UsernameNotFoundException
     * @return errorResponse
     */
    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<ErrorResponse> userNameNotFoundException (UsernameNotFoundException ex) {
        HttpStatus status = HttpStatus.UNAUTHORIZED;

        ErrorResponse errorResponse = new ErrorResponse(
                LocalDateTime.now(),
                status.value(),
                status.getReasonPhrase(),
                ex.getMessage()
        );

        return new ResponseEntity<>(errorResponse, status);
    }
}
