package com.nhnacademy.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.Objects;

/**
 * Member 서비스에 넘겨줄 회원 등록 정보에 대한 응답 DTO입니다.
 */
public class MemberRegisterResponse {

    /** 회원 아이디. */
//    @NotBlank(message = "아이디는 필수 입력 항목입니다.")
    private final String memberId;

    /** 회원 이름. */
//    @NotBlank(message = "이름은 필수 입력 항목입니다.")
//    @Size(min = 2, max = 4, message = "이름은 2자 이상 4자 이하로 입력해 주세요.")
    private final String memberName;

    /** 회원 비밀번호. */
//    @NotBlank(message = "비밀번호는 필수 입력 항목입니다.")
//    @Size(min = 10, max = 20, message = "비밀번호는 10자 이상 20자 이하로 입력해주세요.")
    private final String memberPassword;

    /** 회원 이메일. */
//    @Email(message = "유효한 이메일 주소를 입력해 주세요")
//    @NotBlank(message = "이메일은 필수 입력 항목입니다.")
    private final String memberEmail;

    /** 회원 생년월일. */
//    @NotBlank(message = "생년월일은 필수 입력 항목입니다.")
    private final String memberBirth;

    /** 회원 휴대폰 번호. */
//    @NotBlank(message = "전화번호는 필수 입력 항목입니다.")
//    @Pattern(
//            regexp = "^01[0-9]-\\d{3,4}-\\d{4}$",
//            message = "모바일 연락처는 01X-XXXX-XXXX 형식으로 입력해주세요."
//    )
    private final String memberMobile;

    /** 회원 성별. */
//    @NotBlank(message = "성별은 필수 입력 항목입니다.")
    private final String memberSex;

    /**
     * 회원 등록 응답 생성자.
     *
     * @param memberId       회원 아이디
     * @param memberName     회원 이름
     * @param memberPassword 회원 비밀번호
     * @param memberEmail    회원 이메일
     * @param memberBirth    회원 생년월일
     * @param memberMobile   회원 연락처
     * @param memberSex      회원 성별
     */
    public MemberRegisterResponse(String memberId, String memberName, String memberPassword,
                                  String memberEmail, String memberBirth,
                                  String memberMobile, String memberSex) {
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

    @Override
    public String toString() {
        return "MemberRegisterResponse{" +
                "memberId='" + memberId + '\'' +
                ", memberName='" + memberName + '\'' +
                ", memberPassword='" + memberPassword + '\'' +
                ", memberEmail='" + memberEmail + '\'' +
                ", memberBirth='" + memberBirth + '\'' +
                ", memberMobile='" + memberMobile + '\'' +
                ", memberSex='" + memberSex + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object object) {
        if (!(object instanceof MemberRegisterResponse that)) return false;
        return Objects.equals(memberId, that.memberId)
                && Objects.equals(memberName, that.memberName)
                && Objects.equals(memberPassword, that.memberPassword)
                && Objects.equals(memberEmail, that.memberEmail)
                && Objects.equals(memberBirth, that.memberBirth)
                && Objects.equals(memberMobile, that.memberMobile)
                && Objects.equals(memberSex, that.memberSex);
    }

    @Override
    public int hashCode() {
        return Objects.hash(memberId,
                memberName,
                memberPassword,
                memberEmail,
                memberBirth,
                memberMobile,
                memberSex);
    }
}
