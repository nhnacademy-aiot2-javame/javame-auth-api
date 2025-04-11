package com.nhnacademy.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;

import java.util.Objects;

/**
 * JWT 토큰 정보를 담는 DTO 클래스입니다.
 */
public class JwtTokenDto {

    /**
     * 토큰 타입 (예: Bearer).
     */
    @JsonProperty("tokenType")
    private String tokenType;

    /**
     * 액세스 토큰.
     * -- GETTER --
     *  액세스 토큰을 반환합니다.
     *
     * @return 액세스 토큰

     */
    @Getter
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
     * @param tokenType    토큰 타입
     * @param accessToken  액세스 토큰
     * @param refreshToken 리프레시 토큰
     */
    public JwtTokenDto(String tokenType, String accessToken, String refreshToken) {
        this.tokenType = tokenType;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    /**
     * 토큰 타입을 반환합니다.
     *
     * @return 토큰 타입
     */
    public String getTokenType() {
        return tokenType;
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

    @Override
    public String toString() {
        return "JwtTokenDto{" +
                "tokenType='" + tokenType + '\'' +
                ", accessToken='" + accessToken + '\'' +
                ", refreshToken='" + refreshToken + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object object) {
        if (!(object instanceof JwtTokenDto that)) {
            return false;
        }

        return Objects.equals(tokenType, that.tokenType)
                && Objects.equals(accessToken, that.accessToken)
                && Objects.equals(refreshToken, that.refreshToken);
    }

    @Override
    public int hashCode() {
        return Objects.hash(tokenType, accessToken, refreshToken);
    }
}
