package com.nhnacademy.auth;

import com.nhnacademy.auth.company.adaptor.CompanyAdaptor;
import com.nhnacademy.auth.company.request.CompanyUpdateEmailRequest;
import com.nhnacademy.auth.config.IpUtil;
import com.nhnacademy.auth.member.adaptor.MemberAdaptor;
import com.nhnacademy.auth.member.request.MemberPasswordChangeRequest;
import com.nhnacademy.auth.member.response.MemberResponse;
import com.nhnacademy.auth.provider.JwtTokenProvider;
import com.nhnacademy.auth.repository.RefreshTokenRepository;
import com.nhnacademy.auth.token.JwtTokenDto;
import com.nhnacademy.auth.token.RefreshToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.file.AccessDeniedException;
import java.util.Objects;
import java.util.Optional;

/**
 *  login, logout, signup 을 당담하는 Controller입니다.
 *  gateway 에서 /api/auth/** 으로 들어오는 경로를 api를 제거하여 /auth/** 으로 들어오는 것들을 처리합니다.
 */
@RestController
@RequestMapping("/auth")
@Slf4j
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
     * 암호화를 위한 PasswordEncoder.
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
     * 로그아웃 요청을 처리합니다.
     *
     * @param request 프론트로부터 담겨진 쿠키를 가져옴.
     * @param response 쿠키를 제거함.
     * @return 리다이렉트 응답
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new InsufficientAuthenticationException("로그인 상태가 아닙니다.");
        }
        String userEmail = authentication.getName(); // JwtFilter나 HeaderFilter에서 set한 이메일
        refreshTokenRepository.deleteById(DigestUtils.sha256Hex(tokenPrefix + ":" + userEmail)); // Redis or DB에서 삭제

        return ResponseEntity.ok().build();
    }

    @GetMapping("/refresh")
    public ResponseEntity<JwtTokenDto> refresh(HttpServletRequest request, HttpServletResponse response) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new InsufficientAuthenticationException("로그인 상태가 아닙니다.");
        }
        String userEmail = authentication.getName();
        String userRole = authentication.getAuthorities().stream()
                .findFirst()
                .map(GrantedAuthority::getAuthority)
                .orElse(null);
        String refreshTokenId = DigestUtils.sha256Hex(tokenPrefix + ":" + userEmail);

        Optional<RefreshToken> optionalToken = refreshTokenRepository.findById(refreshTokenId);
        if (optionalToken.isEmpty()) {
            log.info("RefreshTokenRepository Not found : 유효한 Refresh Token이 아닙니다.");
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setHeader("X-Refresh-Required", "true");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        JwtTokenDto jwtTokenDto = jwtTokenProvider.generateTokenDto(userEmail, userRole);
        RefreshToken savedToken = new RefreshToken(DigestUtils.sha256Hex(tokenPrefix + ":" + userEmail),
                jwtTokenDto.getRefreshToken(),
                request.getHeader("User-Agent"),
                IpUtil.getClientIp(request));
        log.info("--- new token provide and save ---");
        refreshTokenRepository.save(savedToken);
        return ResponseEntity.ok(jwtTokenDto);
    }

    @PatchMapping("/update/password")
    public ResponseEntity<Void> updatePassword(HttpServletRequest request,
                                               @RequestBody MemberPasswordChangeRequest passwordUpdateRequest) {
        log.info("request class: {}", request.getClass().getName());
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new InsufficientAuthenticationException("로그인 상태가 아닙니다.");
        }

        String userEmail = authentication.getName(); // JwtFilter나 HeaderFilter에서 set한 이메일

        MemberResponse member = memberAdaptor.getMemberByEmail(userEmail).getBody();

        MemberPasswordChangeRequest encodeRequest = new MemberPasswordChangeRequest(passwordUpdateRequest.getCurrentPassword(),
                                                                                    passwordUpdateRequest.getNewPassword());

        memberAdaptor.changeMemberPassword(Objects.requireNonNull(member).getMemberNo(), encodeRequest, userEmail);

        return ResponseEntity.ok().build();
    }

    @PatchMapping("/update/{companyDomain}/email")
    public ResponseEntity<Void> updateEmail(HttpServletRequest request,
                                            @PathVariable String companyDomain,
                                            @RequestBody CompanyUpdateEmailRequest emailRequest) throws AccessDeniedException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new InsufficientAuthenticationException("로그인 상태가 아닙니다.");
        }

        String userEmail = authentication.getName();
        String userRole = authentication.getAuthorities().stream()
                .findFirst()
                .map(GrantedAuthority::getAuthority)
                .orElse(null);

        if (!userEmail.equals(emailRequest.getCurrentEmail())) {
            throw new AccessDeniedException("인증된 사용자와 요청한 이메일이 일치하지 않습니다.");
        }
        if (!Objects.equals(userRole, "ROLE_OWNER")) {
            throw new AccessDeniedException("이메일 변경 권한이 없습니다.");
        }

        companyAdaptor.updateCompanyEmail(companyDomain, emailRequest);
        return ResponseEntity.ok().build();
    }
}
