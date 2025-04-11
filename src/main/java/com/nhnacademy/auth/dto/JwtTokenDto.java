package com.nhnacademy.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

public class JwtTokenDto {

    @JsonProperty("tokenType")
    private String tokenType;

    @JsonProperty("accessToken")
    private String accessToken;

    @JsonProperty("refreshToken")
    private String refreshToken;

    public JwtTokenDto(){}

    public JwtTokenDto(String tokenType, String accessToken, String refreshToken) {
        this.tokenType = tokenType;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    public String getGrantType() {
        return tokenType;
    }

    public String getAccessToken() {
        return accessToken;
    }

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
        if (!(object instanceof JwtTokenDto that)) return false;
        return Objects.equals(tokenType, that.tokenType) && Objects.equals(accessToken, that.accessToken) && Objects.equals(refreshToken, that.refreshToken);
    }

    @Override
    public int hashCode() {
        return Objects.hash(tokenType, accessToken, refreshToken);
    }
}
