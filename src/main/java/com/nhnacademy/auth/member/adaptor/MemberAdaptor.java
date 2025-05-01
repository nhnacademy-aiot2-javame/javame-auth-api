package com.nhnacademy.auth.member.adaptor;

import com.nhnacademy.auth.member.request.MemberPasswordChangeRequest;
import com.nhnacademy.auth.member.request.MemberRegisterRequest;
import com.nhnacademy.auth.member.response.MemberLoginResponse;
import com.nhnacademy.auth.member.response.MemberResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

/**
 *  front 에서도 통신할 수 있는 Adaptor.
 */
@FeignClient(name = "member-api", contextId = "memberClient")
public interface MemberAdaptor {

    @PostMapping("/members")
    ResponseEntity<MemberResponse> registerMember(@Validated @RequestBody MemberRegisterRequest request);

    @PostMapping("/members/owner")
    ResponseEntity<MemberResponse> registerOwner(@Validated @RequestBody MemberRegisterRequest request);

    @GetMapping("/members/{memberNo}")
    ResponseEntity<MemberResponse> getMemberById(@PathVariable Long memberNo);

    @PutMapping("/members/{memberNo}/password")
    ResponseEntity<Void> changeMemberPassword(@PathVariable Long memberNo,
                                                @Validated @RequestBody MemberPasswordChangeRequest request);

    @DeleteMapping("/members/{memberNo}")
    ResponseEntity<Void> deleteMember(@PathVariable Long memberNo);

    @GetMapping("/login-info/{email}")
    ResponseEntity<MemberLoginResponse> getLoginInfoByEmail(@PathVariable String email);

    @GetMapping("/members/member-email")
    ResponseEntity<MemberResponse> getMemberByEmail(@RequestBody String memberEmail);

    @PutMapping("/members/last-login")
    ResponseEntity<Void> updateLastLogin(@RequestBody String memberEmail);
}
