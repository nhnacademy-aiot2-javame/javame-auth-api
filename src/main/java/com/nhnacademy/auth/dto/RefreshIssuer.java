package com.nhnacademy.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public class RefreshIssuer {

    @JsonProperty("refreshToken")
    private String refreshToken;

    @JsonProperty("memberId")
    private String memberId;

    public RefreshIssuer() {}

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
}
