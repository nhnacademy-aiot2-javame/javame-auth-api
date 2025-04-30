package com.nhnacademy.auth.company.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 신규 회사 등록을 요청할 때 필요한 데이터를 담는 DTO 클래스입니다.
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class CompanyWithOwnerRegisterRequest {

    /**
     * 등록할 회사의 고유 도메인 (기본키).
     */
    @JsonProperty
    private String companyDomain;

    /**
     * 등록할 회사의 이름.
     */
    @JsonProperty
    private String companyName;

    /**
     * 등록할 회사의 대표 이메일.
     */
    @JsonProperty
    private String companyEmail;

    /**
     * 등록할 회사의 대표 연락처.
     */
    @JsonProperty
    private String companyMobile;

    /**
     * 등록할 회사의 주소.
     */
    @JsonProperty
    private String companyAddress;

    /**
     * 등록할 회사의 대표 회원 이메일.
     */
    @JsonProperty
    private String ownerEmail;

    /**
     * 등록할 회사의 대표 회원 비밀번호.
     */
    @JsonProperty
    private String ownerPassword;

}
