package com.nhnacademy.auth;

import com.nhnacademy.auth.company.adaptor.CompanyAdaptor;
import com.nhnacademy.auth.company.request.CompanyUpdateEmailRequest;
import com.nhnacademy.auth.member.adaptor.MemberAdaptor;
import com.nhnacademy.auth.member.request.MemberPasswordChangeRequest;
import com.nhnacademy.auth.member.request.MemberRegisterRequest;
import com.nhnacademy.auth.member.response.MemberResponse;
import com.nhnacademy.auth.provider.JwtTokenProvider;
import com.nhnacademy.auth.repository.RefreshTokenRepository;
import com.nhnacademy.auth.token.JwtTokenDto;
import com.nhnacademy.auth.token.RefreshToken;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


import java.net.URI;
import java.nio.file.AccessDeniedException;
import java.util.Map;
import java.util.Objects;

/**
 *  login, logout, signup 을 당담하는 Controller입니다.
 *  gateway 에서 /api/auth/** 으로 들어오는 경로를 api를 제거하여 /auth/** 으로 들어오는 것들을 처리합니다.
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    /**
     * MEMBER-API의 CompanyController와 통신하는 adaptor.
     */
    private final CompanyAdaptor companyAdaptor;

    /**
     *  redis key 값에 추가할 prefix.
     */
    @Value("${token.prefix}")
    private String tokenPrefix;

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
     * @param companyAdaptor 회사 어댑터
     */
    public AuthController(MemberAdaptor memberAdaptor,
                          PasswordEncoder passwordEncoder,
                          JwtTokenProvider jwtTokenProvider,
                          RefreshTokenRepository refreshTokenRepository, CompanyAdaptor companyAdaptor) {
        this.memberAdaptor = memberAdaptor;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
        this.refreshTokenRepository = refreshTokenRepository;
        this.companyAdaptor = companyAdaptor;
    }

    /**
     * 회원가입 요청을 처리합니다.
     *
     * @param request 회원가입 요청 DTO
     * @return 리다이렉트 응답
     */
    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> signup(@Valid @RequestBody MemberRegisterRequest request) {
        String encodedPassword = passwordEncoder.encode(request.getMemberPassword());

        MemberRegisterRequest encodeRequest = new MemberRegisterRequest(
                request.getMemberEmail(),
                encodedPassword,
                request.getCompanyDomain());

        memberAdaptor.registerMember(encodeRequest);

        Map<String, String> body = Map.of("message", "회원가입 성공");

        return ResponseEntity.status(HttpStatus.CREATED).body(body);
    }


    /**
     * 로그아웃 요청을 처리합니다.
     *
     * @param request 프론트로부터 담겨진 쿠키를 가져옴.
     * @param response 쿠키를 제거함.
     * @return 리다이렉트 응답
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        String token = jwtTokenProvider.resolveTokenFromCookie(request); // 쿠키에서 토큰 꺼냄
        String username = jwtTokenProvider.getUserEmailFromToken(token);
        refreshTokenRepository.deleteById(DigestUtils.sha256Hex(tokenPrefix + ":" + username)); // Redis or DB에서 삭제

        // Cookie 제거
        Cookie expiredCookie = new Cookie("accessToken", null);
        expiredCookie.setHttpOnly(true); //JS 접근 불가.
        expiredCookie.setSecure(true); //HTTPS 전용
        expiredCookie.setPath("/");
        expiredCookie.setMaxAge(0);
        response.addCookie(expiredCookie);

        return ResponseEntity.ok().build();
    }

    @GetMapping("/refresh")
    public ResponseEntity<JwtTokenDto> refresh(HttpServletRequest request) {
        //gateway가 refresh token을 검증해줬으므로 믿고 사용하겠음.
        String refreshToken = jwtTokenProvider.resolveTokenFromCookie(request);
        String userId = jwtTokenProvider.getUserEmailFromToken(refreshToken);
        String userRole = jwtTokenProvider.getRoleIdFromToken(refreshToken);

        String refreshTokenId = DigestUtils.sha256Hex(tokenPrefix + ":" + userId);

        if (refreshTokenRepository.existsById(refreshTokenId)) {
            JwtTokenDto jwtTokenDto = jwtTokenProvider.generateTokenDto(userId, userRole);
            RefreshToken savedToken = new RefreshToken(DigestUtils.sha256Hex(tokenPrefix + ":" + userId), refreshToken);
            refreshTokenRepository.save(savedToken);

            return ResponseEntity.ok(jwtTokenDto);
        }

        //body에 null을 넣어주면 빈 문자열을 반환합니다.
        //만일 null을 기대한다면 "null"로 넣어주면 됩니다.
        return ResponseEntity.ok(null);
    }

    @PatchMapping("/update/password")
    public ResponseEntity<Void> updatePassword(HttpServletRequest request,
                                               @RequestBody MemberPasswordChangeRequest passwordUpdateRequest) {

        String accessToken = jwtTokenProvider.resolveTokenFromCookie(request);
        String userId = jwtTokenProvider.getUserEmailFromToken(accessToken);
        MemberResponse member = memberAdaptor.getMemberByEmail(userId).getBody();

        String encodeCurrentPassword = passwordEncoder.encode(passwordUpdateRequest.getCurrentPassword());
        String encodeNewPassword = passwordEncoder.encode(passwordUpdateRequest.getNewPassword());
        MemberPasswordChangeRequest encodeRequest = new MemberPasswordChangeRequest(encodeCurrentPassword,
                                                                                    encodeNewPassword);

        memberAdaptor.changeMemberPassword(Objects.requireNonNull(member).getMemberNo(), encodeRequest);

        return ResponseEntity.ok().build();
    }

    @PatchMapping("/update/{companyDomain}/email")
    public ResponseEntity<Void> updateEmail(HttpServletRequest request,
                                            @PathVariable String companyDomain,
                                            @RequestBody CompanyUpdateEmailRequest emailRequest) throws AccessDeniedException {

        String authenticatedEmail = SecurityContextHolder.getContext().getAuthentication().getName();

        String accessToken = jwtTokenProvider.resolveTokenFromCookie(request);
        String roleId = jwtTokenProvider.getRoleIdFromToken(accessToken);

        if (!authenticatedEmail.equals(emailRequest.getCurrentEmail())) {
            throw new AccessDeniedException("인증된 사용자와 요청한 이메일이 일치하지 않습니다.");
        }
        if (!Objects.equals(roleId, "ROLE_OWNER")) {
            throw new AccessDeniedException("이메일 변경 권한이 없습니다.");
        }

        companyAdaptor.updateCompanyEmail(companyDomain, emailRequest);
        return ResponseEntity.ok().build();
    }


}
