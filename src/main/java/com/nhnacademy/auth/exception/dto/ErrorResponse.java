
package com.nhnacademy.auth.exception.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;

import java.time.LocalDateTime;

/**
 * API 에러 발생 시 클라이언트에 반환될 표준 응답 형식을 정의하는 DTO 클래스입니다.
 */
@Getter
public class ErrorResponse {

    /**
     * 에러가 발생한 시간.
     */
    @JsonProperty
    private final LocalDateTime timestamp;

    /**
     * 에러 상태.
     */
    @JsonProperty
    private final int status;

    /**
     * 에러.
     */
    @JsonProperty
    private final String error;

    /**
     * 에러에 관한 메세지.
     */
    @JsonProperty
    private final String message;

    public ErrorResponse(LocalDateTime timestamp, int status, String error, String message) {
        this.timestamp = timestamp; // 에러 발생 시간 초기화
        this.status = status;       // HTTP 상태 코드 초기화
        this.error = error;         // HTTP 상태 메시지 초기화
        this.message = message;     // 에러 메시지 초기화
    }
}
