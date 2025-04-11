package com.nhnacademy.auth.adaptor;

import com.nhnacademy.auth.dto.LoginResponse;
import com.nhnacademy.auth.dto.MemberRegisterResponse;
import com.nhnacademy.auth.dto.MemberResponse;
import org.apache.catalina.authenticator.SavedRequest;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

/**
 *  front 에서도 통신할 수 있는 Adaptor.
 */
@FeignClient(name = "MEMBER-API")
public interface MemberAdaptor {

    @PostMapping()
    ResponseEntity<MemberResponse> registerMember(@Validated @RequestBody MemberRegisterResponse memberRegisterResponse);

    @GetMapping("/{member-id}")
    ResponseEntity<MemberResponse> getMember(@PathVariable("member-id") String memberId);

    @GetMapping()
    LoginResponse getLoginInfo(String username);
}
