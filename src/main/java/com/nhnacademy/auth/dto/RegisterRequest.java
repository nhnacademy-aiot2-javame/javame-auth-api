package com.nhnacademy.auth.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;

/**
 * Front에서 받을 회원 등록 정보에 대한 DTO입니다.
 */
public class RegisterRequest {
    /** 회사 도메인. */
    @NotBlank(message = "회사 도메인은 필수 입력 항목입니다.")
    private String companyDomain;

    /**
     * 회원 비밀번호.
     * 영어 대소문자 및 특수문자를 포함해야 합니다.
     */
    @JsonProperty
    @NotBlank(message = "비밀번호는 필수 입력 항목입니다.")
    @Size(min = 8, max = 16, message = "비밀번호는 8자 이상 16자 이하로 입력해주세요.")
    @Pattern(
            regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+\\-="
                    + "\\[\\]{};':\"\\\\|,.<>\\/?]).{10,}$",
            message = "비밀번호는 최소 8자리 이상, 영어 대소문자 + 특수문자 포함"
    )
    private String memberPassword;

    /**
     * 회원 이메일.
     */
    @JsonProperty
    @Email(message = "유효한 이메일 주소를 입력해 주세요")
    @NotBlank(message = "이메일은 필수 입력 항목입니다.")
    private String memberEmail;


    /**
     * 회원 연락처.
     * 형식: 01X-XXXX-XXXX
     */
    @JsonProperty
    @NotBlank(message = "전화번호는 필수 입력 항목입니다.")
    @Pattern(
            regexp = "^01[0-9]-\\d{3,4}-\\d{4}$",
            message = "모바일 연락처는 01X-XXXX-XXXX 형식으로 입력해주세요."
    )
    private String memberMobile;


    /**
     * 회원 등록 요청 생성자.
     *
     * @param companyDomain 회사 도메인
     * @param memberPassword 회원 비밀번호
     * @param memberEmail   회원 이메일
     * @param memberMobile  회원 연락처
     */
    @JsonCreator
    public RegisterRequest(String companyDomain, String memberPassword,
                           String memberEmail,
                           String memberMobile) {
        this.companyDomain = companyDomain;

        this.memberPassword = memberPassword;
        this.memberEmail = memberEmail;
        this.memberMobile = memberMobile;
    }

    public String getCompanyDomain() {
        return companyDomain;
    }

    public String getMemberPassword() {
        return memberPassword;
    }

    public String getMemberEmail() {
        return memberEmail;
    }


    @Override
    public String toString() {
        return "RegisterRequest{" +
                "companyDomain='" + companyDomain + '\'' +
                ", memberPassword='" + memberPassword + '\'' +
                ", memberEmail='" + memberEmail + '\'' +
                ", memberMobile='" + memberMobile + '\'' +
                '}';
    }
}
