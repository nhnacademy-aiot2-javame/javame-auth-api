package com.nhnacademy.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.util.Objects;

/**
 * Member 서비스가 넘겨줄 회원 등록 정보에 대한 응답 DTO입니다.
 */
public class MemberRegisterResponse {
    /** 회사 도메인. */
    @NotBlank(message = "회사 도메인은 필수 입력 항목입니다.")
    private String companyDomain;

    /** 회원 이메일. */
    @Email(message = "유효한 회사 이메일 주소를 입력해 주세요")
    @NotBlank(message = "회사 이메일은 필수 입력 항목입니다.")
    private String memberEmail;

    /** 회원 비밀번호. */
    @NotBlank(message = "비밀번호는 필수 입력 항목입니다.")
    @Size(min = 8, max = 16, message = "비밀번호는 8자 이상 16자 이하로 입력해주세요.")
    private String memberPassword;

    /**
     * @param companyDomain
     * @param memberEmail
     * @param memberPassword
     */
    public MemberRegisterResponse(String companyDomain, String memberEmail, String memberPassword) {
        this.companyDomain = companyDomain;
        this.memberEmail = memberEmail;
        this.memberPassword = memberPassword;
    }

    public String getMemberPassword() {
        return memberPassword;
    }

    public String getMemberEmail() {
        return memberEmail;
    }


    public String getCompanyDomain() {
        return companyDomain;
    }

    @Override
    public String toString() {
        return "MemberRegisterResponse{" +
                "companyDomain='" + companyDomain + '\'' +
                ", memberEmail='" + memberEmail + '\'' +
                ", memberPassword='" + memberPassword + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object object) {
        if (!(object instanceof MemberRegisterResponse that)) return false;
        return Objects.equals(companyDomain, that.companyDomain) && Objects.equals(memberEmail, that.memberEmail) && Objects.equals(memberPassword, that.memberPassword);
    }

    @Override
    public int hashCode() {
        return Objects.hash(companyDomain, memberEmail, memberPassword);
    }
}
