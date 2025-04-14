package com.nhnacademy.auth.service;

import com.nhnacademy.auth.adaptor.MemberAdaptor;
import com.nhnacademy.auth.dto.JwtTokenDto;
import com.nhnacademy.auth.dto.RegisterRequest;
import com.nhnacademy.auth.dto.MemberRegisterResponse;
import com.nhnacademy.auth.dto.RefreshIssuer;
import com.nhnacademy.auth.provider.JwtTokenProvider;
import feign.FeignException;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

/**
 *  login, logout, signup 을 당담하는 Controller입니다.
 */
@CrossOrigin(origins = "http://localhost:10251")
@RestController
@RequestMapping("/auth")
@Slf4j
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
    public ResponseEntity<Void> signup(@Valid @RequestBody RegisterRequest registerRequest) { // 프론트 -> Auth 로 들어오는 DTO
        log.info("회원가입 요청 수신: {}", registerRequest.getMemberId()); // 로깅 추가 권장
        try {
            // 1. 비밀번호 해싱
            String encodedPassword = passwordEncoder.encode(registerRequest.getMemberPassword());

            // 2. MemberAdaptor로 전달할 DTO 생성 (RegisterRequest 타입 사용)
            //    Auth 서비스의 RegisterRequest 와 Member API의 MemberRegisterRequest 필드가 동일하다고 가정
            RegisterRequest memberApiRequest = new RegisterRequest( // <<<--- 타입을 RegisterRequest로 변경
                    registerRequest.getMemberId(),
                    registerRequest.getMemberName(),
                    encodedPassword, // 해싱된 비밀번호 사용
                    registerRequest.getMemberEmail(),
                    registerRequest.getMemberBirth(),
                    registerRequest.getMemberMobile(),
                    registerRequest.getMemberSex(),
                    registerRequest.getRoleId()
            );

            // 3. MemberAdaptor를 통해 Member API 회원가입 호출
            log.debug("Member API 회원가입 호출 시작: {}", memberApiRequest.getMemberId());
            memberAdaptor.registerMember(memberApiRequest); // <<<--- 올바른 타입의 객체 전달
            log.info("Member API 회원가입 호출 성공: {}", memberApiRequest.getMemberId());

            // 4. 성공 시 201 Created 응답 반환
            return ResponseEntity.status(HttpStatus.CREATED).build();


        } catch (FeignException fe) { // <<<--- Feign 예외 처리 추가 권장
            log.error("Member API 호출 실패: status={}, body={}, id={}", fe.status(), fe.contentUTF8(), registerRequest.getMemberId(), fe);
            if (fe.status() == HttpStatus.CONFLICT.value()) {
                return ResponseEntity.status(HttpStatus.CONFLICT).build();
            } else if (fe.status() >= 400 && fe.status() < 500) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
            }
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        } catch (Exception e) {
            log.error("회원가입 처리 중 알 수 없는 오류 발생: id={}", registerRequest.getMemberId(), e); // <<<--- 로깅 추가 권장
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
