
package com.nhnacademy.auth.dto;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

/**
 * meber 서비스에서 회원 정보를 응답할 때 사용하는 DTO입니다.
 */

@NoArgsConstructor
@AllArgsConstructor
public class MemberResponse {

    /** 회원 번호. */
    private Long memberNo;

    /** 회원 아이디. */
    private String memberId;

    /** 회원 이름. */
    private String memberName;

    /** 회원 이메일. */
    private String memberEmail;

    /** 회원 성별. */
    private String memberSex;

    /** 회원 역할 ID. */
    private String roleId;

    public Long getMemberNo() {
        return memberNo;
    }

    public String getMemberId() {
        return memberId;
    }

    public String getMemberName() {
        return memberName;
    }

    public String getMemberEmail() {
        return memberEmail;
    }

    public String getMemberSex() {
        return memberSex;
    }

    public String getRoleId() {
        return roleId;
    }
}