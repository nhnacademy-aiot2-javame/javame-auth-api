
package com.nhnacademy.auth.dto;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

/**
 * meber 서비스에서 회원 정보를 응답할 때 사용하는 DTO입니다.
 */

@NoArgsConstructor
@AllArgsConstructor
public class MemberResponse {

    /** 회원 아이디. */
    private String memberId;

    /** 회사 도메인. */
    private String companyDomain;

    /** 회원 역할 ID. */
    private String roleId;

    /** 회원 이메일. - 로그인 시 사용하는 아이디 */
    private String memberEmail;
}