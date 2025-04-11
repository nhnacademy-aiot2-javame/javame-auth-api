package com.nhnacademy.auth.service;

import com.nhnacademy.auth.adaptor.MemberAdaptor;
import com.nhnacademy.auth.dto.JwtTokenDto;
import com.nhnacademy.auth.dto.MemberRegisterRequest;
import com.nhnacademy.auth.dto.RefreshIssuer;
import com.nhnacademy.auth.provider.JwtTokenProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.net.URI;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final MemberAdaptor memberAdaptor;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    public AuthController(MemberAdaptor memberAdaptor, PasswordEncoder passwordEncoder, JwtTokenProvider jwtTokenProvider){
        this.memberAdaptor = memberAdaptor;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @PostMapping("/signup")
    public ResponseEntity<Void> signup(@Validated @RequestBody MemberRegisterRequest memberRegisterRequest){
        // 비밀번호 인코딩
        String encodedPassword = passwordEncoder.encode(memberRegisterRequest.getMemberPassword());

        MemberRegisterRequest encodeRequest = new MemberRegisterRequest(
                memberRegisterRequest.getMemberId(),
                memberRegisterRequest.getMemberName(),
                encodedPassword,
                memberRegisterRequest.getMemberEmail(),
                memberRegisterRequest.getMemberBirth(),
                memberRegisterRequest.getMemberMobile(),
                memberRegisterRequest.getMemberSex()
        );

        memberAdaptor.registerMember(encodeRequest);

        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(URI.create("https://javame.live/auth/login"));

        return ResponseEntity.status(HttpStatus.TEMPORARY_REDIRECT)
                .headers(headers)
                .build();
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
    public ResponseEntity<JwtTokenDto> refresh(@RequestBody RefreshIssuer refreshIssuer){
        //gateway가 refresh token을 검증해줬으므로 믿고 사용하겠음.
        String refreshToken = refreshIssuer.getRefreshToken();
        JwtTokenDto jwtTokenDto = jwtTokenProvider.generateTokenDto(refreshIssuer.getMemberId());
        return ResponseEntity.ok(jwtTokenDto);
    }
}
