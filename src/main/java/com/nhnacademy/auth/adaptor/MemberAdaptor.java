package com.nhnacademy.auth.adaptor;

import com.nhnacademy.auth.dto.LoginResponse;
import com.nhnacademy.auth.dto.MemberResponse;
import com.nhnacademy.auth.dto.RegisterRequest;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;


/**
 *  front 에서도 통신할 수 있는 Adaptor.
 */
@FeignClient(name = "MEMBER-API")
public interface MemberAdaptor {


    /**
     * 사용자 ID를 기반으로 로그인에 필요한 정보(ID, 해싱된 PW, 역할 ID 등)를 조회합니다.
     * Auth 서비스의 UserDetailsService에서 사용됩니다.
     * Member API의 LoginController (GET /login/{memberId})를 호출합니다.
     *
     * @param memberId 조회할 사용자의 ID
     * @return 로그인 정보 DTO
     */
    @GetMapping("/login/{memberId}") // <<<--- 수정: LoginController의 내부 경로
    LoginResponse getLoginInfoByMemberId(@PathVariable("memberId") String memberId);

    /**
     * 회원 가입 정보를 Member API에 전달하여 등록을 요청합니다.
     * Auth 서비스의 AuthController에서 사용됩니다.
     * Member API의 MemberController (POST /api/v1/members)를 호출합니다.
     *
     * @param request 회원 가입 정보 DTO
     * @return Member API의 응답 (MemberResponse)
     */
    @PostMapping("/api/v1/members") // <<<--- 수정: MemberController의 내부 경로
    ResponseEntity<MemberResponse> registerMember(@RequestBody RegisterRequest request);

}
