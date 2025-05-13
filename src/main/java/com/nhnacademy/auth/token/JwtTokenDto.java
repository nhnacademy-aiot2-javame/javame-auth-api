package com.nhnacademy.auth.token;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.EqualsAndHashCode;
import lombok.ToString;

/**
 * JWT 토큰 정보를 담는 DTO 클래스입니다.
 */
@EqualsAndHashCode
@ToString
public class JwtTokenDto {
    /**
     * 액세스 토큰.
     *  액세스 토큰을 반환합니다.
     *
     * @return 액세스 토큰

     */
    @JsonProperty("accessToken")
    private String accessToken;

    /**
     * 리프레시 토큰.
     */
    @JsonProperty("refreshToken")
    private String refreshToken;

    /**
     * 기본 생성자.
     */
    public JwtTokenDto() {
    }

    /**
     * 모든 필드를 초기화하는 생성자입니다.
     *
     * @param accessToken  액세스 토큰
     * @param refreshToken 리프레시 토큰
     */
    public JwtTokenDto(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    /**
     * AT를 반환합니다.
     * @return AT
     */
    public String getAccessToken() {
        return accessToken;
    }

    /**
     * 리프레시 토큰을 반환합니다.
     *
     * @return 리프레시 토큰
     */
    public String getRefreshToken() {
        return refreshToken;
    }
}
