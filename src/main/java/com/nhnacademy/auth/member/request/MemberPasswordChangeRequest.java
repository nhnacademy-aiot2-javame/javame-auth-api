package com.nhnacademy.auth.member.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 회원 비밀번호 변경 요청 시 필요한 데이터를 담는 DTO 클래스입니다.
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class MemberPasswordChangeRequest {

    /**
     * 현재 비밀번호.
     */
    private String currentPassword;

    /**
     * 새 비밀번호.
     */
    private String newPassword;
}
