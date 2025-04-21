package com.nhnacademy.auth.service;

import com.nhnacademy.auth.adaptor.MemberAdaptor;
import com.nhnacademy.auth.dto.*;
import com.nhnacademy.auth.provider.JwtTokenProvider;
import com.nhnacademy.auth.repository.RefreshTokenRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


import java.net.URI;

/**
 *  login, logout, signup 을 당담하는 Controller입니다.
 *  gateway 에서 /api/auth/** 으로 들어오는 경로를 api를 제거하여 /auth/** 으로 들어오는 것들을 처리합니다.
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
     * Refresh Token을 담아두는 Repository.
     */
    private final RefreshTokenRepository refreshTokenRepository;

    /**
     * AuthController 생성자.
     *
     * @param memberAdaptor    회원 어댑터
     * @param passwordEncoder  패스워드 인코더
     * @param jwtTokenProvider JWT 토큰 제공자
     * @param refreshTokenRepository refresh Token 저장소
     */
    public AuthController(MemberAdaptor memberAdaptor,
                          PasswordEncoder passwordEncoder,
                          JwtTokenProvider jwtTokenProvider,
                          RefreshTokenRepository refreshTokenRepository) {
        this.memberAdaptor = memberAdaptor;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
        this.refreshTokenRepository = refreshTokenRepository;
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
                registerRequest.getCompanyDomain(),
                registerRequest.getMemberEmail(),
                encodedPassword
        );

        memberAdaptor.registerMember(encodeRequest);

        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(URI.create("https://localhost:10251/auth/login"));

        return ResponseEntity.status(HttpStatus.TEMPORARY_REDIRECT)
                .headers(headers)
                .build();
    }

    @PostMapping("/auth/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        JwtTokenDto token = jwtTokenProvider.resolveTokenFromCookie(request); // 쿠키에서 토큰 꺼냄
        String username = jwtTokenProvider.getUserEmailFromToken(token.getAccessToken());
        refreshTokenRepository.deleteById(passwordEncoder.encode(username)); // Redis or DB에서 삭제

        // Cookie 제거
        Cookie expiredCookie = new Cookie("accessToken", null);
        expiredCookie.setHttpOnly(true);
        expiredCookie.setPath("/");
        expiredCookie.setMaxAge(0);
        response.addCookie(expiredCookie);

        return ResponseEntity.ok().build();
    }

    @GetMapping("/refresh")
    public ResponseEntity<JwtTokenDto> refresh(@RequestBody RefreshIssuer refreshIssuer) {
        //gateway가 refresh token을 검증해줬으므로 믿고 사용하겠음.
        String refreshToken = refreshIssuer.getRefreshToken();
        JwtTokenDto jwtTokenDto = jwtTokenProvider.generateTokenDto(refreshIssuer.getMemberId());
        RefreshToken savedToken = new RefreshToken(passwordEncoder.encode(refreshIssuer.getMemberId()), refreshToken);
        refreshTokenRepository.save(savedToken);
        return ResponseEntity.ok(jwtTokenDto);
    }
}
