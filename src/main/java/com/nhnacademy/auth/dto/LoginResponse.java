package com.nhnacademy.auth.dto;

import java.util.Objects;

/**
 * 로그인 응답 정보를 담는 DTO 클래스입니다.
 */
public class LoginResponse {

    /**
     * 회원 ID.
     * -- GETTER --
     *  회원 ID를 반환합니다.
     *
     */
    private final String memberId;

    /**
     * 회원 비밀번호.
     * -- GETTER --
     *  회원 비밀번호를 반환합니다.
     *
     */
    private final String memberPassword;

    /**
     * 회원 역할 ID.
     * -- GETTER --
     *  회원 역할 ID를 반환합니다.
     *

     */
    private final String roleId;

    /**
     * LoginResponse 객체를 생성합니다.
     *
     * @param memberId       회원 ID
     * @param memberPassword 회원 비밀번호
     * @param roleId         회원 역할 ID
     */
    public LoginResponse(String memberId, String memberPassword, String roleId) {
        this.memberId = memberId;
        this.memberPassword = memberPassword;
        this.roleId = roleId;
    }

    public String getMemberId() {
        return memberId;
    }

    public String getMemberPassword() {
        return memberPassword;
    }

    public String getRoleId() {
        return roleId;
    }

    @Override
    public boolean equals(Object object) {
        if (!(object instanceof LoginResponse that)) return false;
        return Objects.equals(memberId, that.memberId)
                && Objects.equals(memberPassword, that.memberPassword)
                && Objects.equals(roleId, that.roleId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(memberId, memberPassword, roleId);
    }

    @Override
    public String toString() {
        return "LoginResponse{" +
                "memberId='" + memberId + '\'' +
                ", memberPassword='" + memberPassword + '\'' +
                ", roleId='" + roleId + '\'' +
                '}';
    }
}
