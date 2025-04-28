package com.nhnacademy.auth.company.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 회사 정보 조회 응답 시 반환될 데이터를 담는 DTO 클래스입니다.
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class CompanyResponse {

    /**
     * 회사의 고유 도메인 (기본키).
     */
    private String companyDomain;

    /**
     * 회사의 이름.
     */
    private String companyName;

    /**
     * 회사의 대표 이메일.
     */
    private String companyEmail;

    /**
     * 회사의 대표 연락처.
     */
    private String companyMobile;

    /**
     * 회사의 주소.
     */
    private String companyAddress;

    /**
     * 회사 정보 등록 일시.
     */
    private LocalDateTime registeredAt;

    /**
     * 회사의 서비스 활성화 여부.
     */
    private boolean active;
}
