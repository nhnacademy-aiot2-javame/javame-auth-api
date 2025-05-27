package com.nhnacademy.auth.member.adaptor;

import com.nhnacademy.auth.member.request.MemberPasswordChangeRequest;
import com.nhnacademy.auth.member.request.MemberRegisterRequest;
import com.nhnacademy.auth.member.response.MemberLoginResponse;
import com.nhnacademy.auth.member.response.MemberResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;

/**
 *  front 에서도 통신할 수 있는 Adaptor.
 */
@FeignClient(name = "member-api", contextId = "memberClient")
public interface MemberAdaptor {

    @PostMapping("/members")
    ResponseEntity<MemberResponse> registerMember(@Validated @RequestBody MemberRegisterRequest request);

    @PostMapping("/members/owners")
    ResponseEntity<MemberResponse> registerOwner(@Validated @RequestBody MemberRegisterRequest request);

    @GetMapping("/members/{memberNo}")
    ResponseEntity<MemberResponse> getMemberById(@PathVariable Long memberNo);

    @PutMapping("/members/{memberNo}/password")
    ResponseEntity<Void> changeMemberPassword(@PathVariable Long memberNo,
                                              @Validated @RequestBody MemberPasswordChangeRequest request,
                                              @RequestHeader("X-User-Email")String userEmail);

    @DeleteMapping("/members/{memberNo}")
    ResponseEntity<Void> deleteMember(@PathVariable Long memberNo);

    @GetMapping("/members/me/login-info")
    ResponseEntity<MemberLoginResponse> getLoginInfoByEmail(@RequestHeader("X-User-Email")String userEmail);

    @GetMapping("/members/me")
    ResponseEntity<MemberResponse> getMemberByEmail(@RequestHeader("X-User-Email")String userEmail);

    @PutMapping("/members/internal/last-login")
    ResponseEntity<Void> updateLastLogin(@RequestParam String email);
}
