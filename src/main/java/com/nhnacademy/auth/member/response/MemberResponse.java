package com.nhnacademy.auth.member.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 회원 정보 조회 응답 시 반환될 데이터를 담는 DTO 클래스입니다.
 * 비밀번호 등 민감 정보는 포함하지 않습니다.
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class MemberResponse {

    /**
     * 회원 식별 번호.
     */
    private Long memberNo;

    /**
     * 회원 이메일.
     */
    private String memberEmail;

    /**
     * 소속 회사 도메인.
     */
    private String companyDomain;

    /**
     * 역할 ID (예: "ROLE_USER").
     */
    private String roleId;

    /**
     *  등록 날짜.
     */
    private LocalDateTime registerAt;

    /**
     * 마지막으로 로그인 한 날짜.
     */
    private LocalDateTime lastLoginAt;

}
