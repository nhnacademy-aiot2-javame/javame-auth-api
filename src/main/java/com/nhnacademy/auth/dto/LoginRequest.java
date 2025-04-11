package com.nhnacademy.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public class LoginRequest {
    @JsonProperty("id")
    private String id;

    @JsonProperty("password")
    private String password;

    // 기본 생성자 필요 (JSON 역직렬화용)
    public LoginRequest() {}

    public String getId() {
        return id;
    }

    public String getPassword() {
        return password;
    }


}