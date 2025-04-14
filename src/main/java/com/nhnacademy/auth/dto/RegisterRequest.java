package com.nhnacademy.auth.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

// import jakarta.validation.constraints.Email;
// import jakarta.validation.constraints.NotBlank;
// import jakarta.validation.constraints.Pattern;
// import jakarta.validation.constraints.Size;
// import lombok.Getter;

/**
 * Front에서 받을 회원 등록 정보에 대한 DTO입니다.
 */
@Getter
public class RegisterRequest {

    /**
     * 회원 아이디.
     */
    @JsonProperty
//     @NotBlank(message = "아이디는 필수 입력 항목입니다.")
    private final String memberId;

    /**
     * 회원 이름.
     */
    @JsonProperty
//     @NotBlank(message = "이름은 필수 입력 항목입니다.")
//     @Size(min = 2, max = 4, message = "이름은 2자 이상 4자 이하로 입력해 주세요.")
    private final String memberName;

    /**
     * 회원 비밀번호.
     * 영어 대소문자 및 특수문자를 포함해야 합니다.
     */
    @JsonProperty
//     @NotBlank(message = "비밀번호는 필수 입력 항목입니다.")
//     @Size(min = 10, max = 20, message = "비밀번호는 10자 이상 20자 이하로 입력해주세요.")
//     @Pattern(
//             regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+\\-="
//                     + "\\[\\]{};':\"\\\\|,.<>\\/?]).{10,}$",
//             message = "비밀번호는 최소 10자리 이상, 영어 대소문자 + 특수문자 포함"
//     )
    private final String memberPassword;

    /**
     * 회원 이메일.
     */
    @JsonProperty
//     @Email(message = "유효한 이메일 주소를 입력해 주세요")
//     @NotBlank(message = "이메일은 필수 입력 항목입니다.")
    private final String memberEmail;

    /**
     * 회원 생년월일.
     */
    @JsonProperty
//     @NotBlank(message = "생년월일은 필수 입력 항목입니다.")
    private final String memberBirth;

    /**
     * 회원 연락처.
     * 형식: 01X-XXXX-XXXX
     */
    @JsonProperty
//     @NotBlank(message = "전화번호는 필수 입력 항목입니다.")
//     @Pattern(
//             regexp = "^01[0-9]-\\d{3,4}-\\d{4}$",
//             message = "모바일 연락처는 01X-XXXX-XXXX 형식으로 입력해주세요."
//     )
    private final String memberMobile;

    /**
     * 회원 성별.
     */
    @JsonProperty
//     @NotBlank(message = "성별은 필수 입력 항목입니다.")
    private final String memberSex;

    @JsonProperty
    private final String roleId;

    /**
     * 회원 등록 요청 생성자.
     *
     * @param memberId      회원 아이디
     * @param memberName    회원 이름
     * @param memberPassword 회원 비밀번호
     * @param memberEmail   회원 이메일
     * @param memberBirth   회원 생년월일
     * @param memberMobile  회원 연락처
     * @param memberSex     회원 성별
     */
    @JsonCreator
    public RegisterRequest(String memberId, String memberName, String memberPassword,
                           String memberEmail, String memberBirth,
                           String memberMobile, String memberSex, String roleId) {
        this.memberId = memberId;
        this.memberName = memberName;
        this.memberPassword = memberPassword;
        this.memberEmail = memberEmail;
        this.memberBirth = memberBirth;
        this.memberMobile = memberMobile;
        this.memberSex = memberSex;
        this.roleId = roleId;
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

    public String getRoleId() {
        return roleId;
    }

    @Override
    public String toString() {
        return "RegisterRequest{" +
                "memberId='" + memberId + '\'' +
                ", memberName='" + memberName + '\'' +
                ", memberPassword='" + memberPassword + '\'' +
                ", memberEmail='" + memberEmail + '\'' +
                ", memberBirth='" + memberBirth + '\'' +
                ", memberMobile='" + memberMobile + '\'' +
                ", memberSex='" + memberSex + '\'' +
                ", roleId='" + roleId + '\'' +
                '}';
    }
}
