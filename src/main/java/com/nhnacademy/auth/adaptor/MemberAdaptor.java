package com.nhnacademy.auth.adaptor;

import com.nhnacademy.auth.dto.MemberRegisterRequest;
import com.nhnacademy.auth.dto.MemberResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;


@FeignClient(name = "MemberService", url="/api/v1/login")
public interface MemberAdaptor {

    @PostMapping
    public ResponseEntity<MemberResponse> registerMember(@Validated @RequestBody MemberRegisterRequest memberRegisterRequest);

    @GetMapping("/{member-id}")
    public ResponseEntity<MemberResponse> getMember(@PathVariable("member-id") String memberId);
}
