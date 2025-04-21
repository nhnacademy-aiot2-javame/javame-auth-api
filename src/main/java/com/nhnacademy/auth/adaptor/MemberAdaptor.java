package com.nhnacademy.auth.adaptor;

import com.nhnacademy.auth.dto.LoginResponse;
import com.nhnacademy.auth.dto.MemberRegisterResponse;
import com.nhnacademy.auth.dto.MemberResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 *  front 에서도 통신할 수 있는 Adaptor.
 */
@FeignClient(name = "MEMBER-API")
public interface MemberAdaptor {

    @PostMapping("/api/v1/members")
    ResponseEntity<MemberResponse> registerMember(@Validated @RequestBody MemberRegisterResponse memberRegisterResponse);

    @GetMapping("/api/v1/members/{member-id}")
    ResponseEntity<MemberResponse> getMember(@PathVariable("member-id") String memberId);

    @GetMapping("/login/{memberId}") // 경로 변수 이름 통일 권장
    ResponseEntity<LoginResponse> getLoginInfo(@PathVariable("memberId") String memberId);

}
