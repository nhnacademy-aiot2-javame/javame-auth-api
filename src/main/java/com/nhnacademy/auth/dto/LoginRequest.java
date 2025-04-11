package com.nhnacademy.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

/**
 * 로그인 요청에 대한 정보를 담는 DTO 클래스입니다.
 */
public class LoginRequest {

    /**
     * 사용자 아이디.
     * -- GETTER --
     *  사용자 아이디를 반환합니다.
     *

     */
    @JsonProperty("id")
    private String id;

    /**
     * 사용자 비밀번호.
     * -- GETTER --
     *  사용자 비밀번호를 반환합니다.
     *

     */
    @JsonProperty("password")
    private String password;

    /**
     * 기본 생성자 (JSON 역직렬화용).
     */
    public LoginRequest() {
    }

    public String getId() {
        return id;
    }

    public String getPassword() {
        return password;
    }

    @Override
    public String toString() {
        return "LoginRequest{" +
                "id='" + id + '\'' +
                ", password='" + password + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object object) {
        if (!(object instanceof LoginRequest that)) return false;
        return Objects.equals(id, that.id) && Objects.equals(password, that.password);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, password);
    }
}
