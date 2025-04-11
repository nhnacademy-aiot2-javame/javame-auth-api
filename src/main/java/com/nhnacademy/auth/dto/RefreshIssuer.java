package com.nhnacademy.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

/**
 * Refresh Token으로 access token을 재발급하기 위한 정보를 담은 DTO입니다.
 */
public class RefreshIssuer {

    /**
     * refresh 토큰.
     */
    @JsonProperty("refreshToken")
    private String refreshToken;

    /**
     * 재발급을 바라는 user 의 Id.
     */
    @JsonProperty("memberId")
    private String memberId;

    public RefreshIssuer() { }

    public String getRefreshToken() {
        return refreshToken;
    }

    public String getMemberId() {
        return memberId;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public void setMemberId(String memberId) {
        this.memberId = memberId;
    }

    @Override
    public String toString() {
        return "RefreshIssuer{" +
                "refreshToken='" + refreshToken + '\'' +
                ", memberId='" + memberId + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object object) {
        if (!(object instanceof RefreshIssuer that)) return false;
        return Objects.equals(refreshToken, that.refreshToken) && Objects.equals(memberId, that.memberId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(refreshToken, memberId);
    }
}
