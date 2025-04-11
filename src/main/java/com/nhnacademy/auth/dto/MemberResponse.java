package com.nhnacademy.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Getter
@AllArgsConstructor
public class MemberResponse {

    private Long memberNo;

    private String memberId;

    private String memberName;

    private String memberEmail;

    private String memberSex;

    private String roleId;
}
