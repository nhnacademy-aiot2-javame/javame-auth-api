package com.nhnacademy.auth.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
/**
 * Front에서 받을 회원 등록 정보에 대한 DTO입니다.
 */
public class RegisterRequest {

    /**
     * 회원 아이디.
     */
    @JsonProperty
    private final String memberId;

    /**
     * 회원 이름.
     */
    @JsonProperty
    private final String memberName;

    /**
     * 회원 비밀번호.
     * 영어 대소문자 및 특수문자를 포함해야 합니다.
     */
    @JsonProperty
    private final String memberPassword;

    /**
     * 회원 이메일.
     */
    @JsonProperty
    private final String memberEmail;

    /**
     * 회원 생년월일.
     */
    @JsonProperty
    private final String memberBirth;

    /**
     * 회원 연락처.
     * 형식: 01X-XXXX-XXXX
     */
    @JsonProperty
    private final String memberMobile;

    /**
     * 회원 성별.
     */
    @JsonProperty
    private final String memberSex;

    @JsonProperty
    private final String roleId;

    /**
     * 회원 등록 요청 생성자.
     *
     * @param memberId      회원 아이디
     * @param memberName    회원 이름
     * @param memberPassword 회원 비밀번호
     * @param memberEmail   회원 이메일
     * @param memberBirth   회원 생년월일
     * @param memberMobile  회원 연락처
     * @param memberSex     회원 성별
     */
    @JsonCreator
    public RegisterRequest(String memberId, String memberName, String memberPassword,
                           String memberEmail, String memberBirth,
                           String memberMobile, String memberSex, String roleId) {
        this.memberId = memberId;
        this.memberName = memberName;
        this.memberPassword = memberPassword;
        this.memberEmail = memberEmail;
        this.memberBirth = memberBirth;
        this.memberMobile = memberMobile;
        this.memberSex = memberSex;
        this.roleId = roleId;
    }

    public String getMemberId() {
        return memberId;
    }

    public String getMemberName() {
        return memberName;
    }

    public String getMemberPassword() {
        return memberPassword;
    }

    public String getMemberEmail() {
        return memberEmail;
    }

    public String getMemberBirth() {
        return memberBirth;
    }

    public String getMemberMobile() {
        return memberMobile;
    }

    public String getMemberSex() {
        return memberSex;
    }

    public String getRoleId() {
        return roleId;
    }

    @Override
    public String toString() {
        return "RegisterRequest{" +
                "memberId='" + memberId + '\'' +
                ", memberName='" + memberName + '\'' +
                ", memberPassword='" + memberPassword + '\'' +
                ", memberEmail='" + memberEmail + '\'' +
                ", memberBirth='" + memberBirth + '\'' +
                ", memberMobile='" + memberMobile + '\'' +
                ", memberSex='" + memberSex + '\'' +
                ", roleId='" + roleId + '\'' +
                '}';
    }
}
