package com.nhnacademy.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class MemberRegisterRequest {
    @NotBlank(message = "아이디는 필수 입력 항목입니다.")
    private final String memberId;

    @NotBlank(message = "이름은 필수 입력 항목입니다.")
    @Size(min = 2, max = 4, message = "이름은 2자 이상 4자 이하로 입력해 주세요.")
    private final String memberName;

    @NotBlank(message = "비밀번호는 필수 입력 항목입니다.")
    @Size(min = 10, max = 20,  message = "비밀번호는 10자 이상 20자 이하로 입력해주세요.")
    @Pattern(
            regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?]).{10,}$\n",
            message = "비밀번호는 최소 10자리 이상, 영어 대소문자 + 특수문자 포함"
    )
    private final String memberPassword;

    @Email(message = "유효한 이메일 주소를 입력해 주세요")
    @NotBlank(message = "이메일은 필수 입력 항목입니다.")
    private final String memberEmail;

    @NotBlank(message = "생년월일은 필수 입력 항목입니다.")
    private final String memberBirth;

    @NotBlank(message = "전화번호는 필수 입력 항목입니다.")
    @Pattern(
            regexp = "^01[0-9]-\\d{3,4}-\\d{4}$",
            message = "모바일 연락처는 01X-XXXX-XXXX 형식으로 입력해주세요."
    )
    private final String memberMobile;

    @NotBlank(message = "성별은 필수 입력 항목입니다.")
    private final String memberSex;

    public MemberRegisterRequest(String memberId, String memberName, String memberPassword, String memberEmail, String memberBirth, String memberMobile, String memberSex) {
        this.memberId = memberId;
        this.memberName = memberName;
        this.memberPassword = memberPassword;
        this.memberEmail = memberEmail;
        this.memberBirth = memberBirth;
        this.memberMobile = memberMobile;
        this.memberSex = memberSex;
    }

    public String getMemberId() {
        return memberId;
    }

    public String getMemberName() {
        return memberName;
    }

    public String getMemberPassword() {
        return memberPassword;
    }

    public String getMemberEmail() {
        return memberEmail;
    }

    public String getMemberBirth() {
        return memberBirth;
    }

    public String getMemberMobile() {
        return memberMobile;
    }

    public String getMemberSex() {
        return memberSex;
    }
}
