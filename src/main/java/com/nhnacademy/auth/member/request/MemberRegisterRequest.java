package com.nhnacademy.auth.member.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 회원 가입 요청 시 필요한 데이터를 담는 DTO 클래스입니다.
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class MemberRegisterRequest {

    /**
     * 이메일.
     */
    private String memberEmail;

    /**
     * 비밀번호.
     */
    private String memberPassword;

    /**
     * 회사 도메인.
     */
    private String companyDomain;

}
