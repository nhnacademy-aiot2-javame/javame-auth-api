package com.nhnacademy.auth.member.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

/**
 * 로그인 요청에 대한 정보를 담는 DTO 클래스입니다.
 */

@Getter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
public class LoginRequest {

    /**
     * 사용자 아이디. 여기선 회사의 email 을 나타냅니다.
     *  사용자 아이디를 반환합니다.
     */
    @JsonProperty("memberEmail")
    private String memberEmail;

    /**
     * 사용자 비밀번호.
     *  사용자 비밀번호를 반환합니다.
     */
    @JsonProperty("memberPassword")
    private String memberPassword;

}
