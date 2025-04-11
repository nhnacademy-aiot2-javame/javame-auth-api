package com.nhnacademy.auth.dto;

public class LoginResponse {

    private final String memberId;

    private final String memberPassword;

    private final String roleId;

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
}
