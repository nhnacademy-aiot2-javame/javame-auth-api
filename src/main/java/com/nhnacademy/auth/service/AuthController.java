package com.nhnacademy.auth.service;

import com.nhnacademy.auth.adaptor.MemberAdaptor;
import com.nhnacademy.auth.dto.JwtTokenDto;
import com.nhnacademy.auth.dto.RegisterRequest;
import com.nhnacademy.auth.dto.MemberRegisterResponse;
import com.nhnacademy.auth.dto.RefreshIssuer;
import com.nhnacademy.auth.provider.JwtTokenProvider;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 *  login, logout, signup 을 당담하는 Controller입니다.
 */
@RestController
@RequestMapping("/auth")

public class AuthController {
    /**
     * 회원가입 및 회원 정보 요청을 위임하는 Adaptor.
     */
    private final MemberAdaptor memberAdaptor;

    /**
     * 비밀번호 암호화를 위한 PasswordEncoder.
     */
    private final PasswordEncoder passwordEncoder;

    /**
     * JWT 토큰 생성 및 검증을 담당하는 Provider.
     */
    private final JwtTokenProvider jwtTokenProvider;

    /**
     * AuthController 생성자.
     *
     * @param memberAdaptor    회원 어댑터
     * @param passwordEncoder  패스워드 인코더
     * @param jwtTokenProvider JWT 토큰 제공자
     */
    public AuthController(MemberAdaptor memberAdaptor,
                          PasswordEncoder passwordEncoder,
                          JwtTokenProvider jwtTokenProvider) {
        this.memberAdaptor = memberAdaptor;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    /**
     * 회원가입 요청을 처리합니다.
     *
     * @param registerRequest 회원가입 요청 DTO
     * @return 리다이렉트 응답
     */
    @PostMapping("/register")
    public ResponseEntity<Void> signup(@Valid @RequestBody RegisterRequest registerRequest) {
        String encodedPassword = passwordEncoder.encode(registerRequest.getMemberPassword());

        MemberRegisterResponse encodeRequest = new MemberRegisterResponse(
                registerRequest.getMemberId(),
                registerRequest.getMemberName(),
                encodedPassword,
                registerRequest.getMemberEmail(),
                registerRequest.getMemberBirth(),
                registerRequest.getMemberMobile(),
                registerRequest.getMemberSex()
        );

        try {
            // MemberAdaptor를 통해 Member API의 회원가입 호출
            memberAdaptor.registerMember(encodeRequest);

            // 성공 시 HTTP 201 Created 반환 (리다이렉트 대신)
            return ResponseEntity.status(HttpStatus.CREATED).build();
        } catch (Exception e) { // 예: FeignException (Member API 호출 실패 등)
            // 적절한 에러 로깅 및 에러 응답 반환 (예: 400, 409, 500)
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

//    @PostMapping("/auth/logout")
//    public ResponseEntity<Void> logout(HttpServletRequest request){
//        String token = jwtTokenProvider.resolveTokenFromCookie(request); // 쿠키에서 토큰 꺼냄
//        String username = jwtTokenProvider.getUsernameFromToken(token);
//
//        refreshTokenStore.deleteByUsername(username); // Redis or DB에서 삭제
//
//        // Cookie 제거
//        Cookie expiredCookie = new Cookie("accessToken", null);
//        expiredCookie.setHttpOnly(true);
//        expiredCookie.setPath("/");
//        expiredCookie.setMaxAge(0);
//        response.addCookie(expiredCookie);
//
//        return ResponseEntity.ok().build();
//    }

    @GetMapping("/refresh")
    public ResponseEntity<JwtTokenDto> refresh(@RequestBody RefreshIssuer refreshIssuer) {
        //gateway가 refresh token을 검증해줬으므로 믿고 사용하겠음.
        String refreshToken = refreshIssuer.getRefreshToken();
        JwtTokenDto jwtTokenDto = jwtTokenProvider.generateTokenDto(refreshIssuer.getMemberId());
        return ResponseEntity.ok(jwtTokenDto);
    }
}
