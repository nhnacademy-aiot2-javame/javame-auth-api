package com.nhnacademy.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nhnacademy.auth.context.ApplicationContextHolder;
import com.nhnacademy.auth.detail.MemberDetails;
import com.nhnacademy.auth.event.LoginSuccessEvent;
import com.nhnacademy.auth.token.JwtTokenDto;
import com.nhnacademy.auth.member.request.LoginRequest;
import com.nhnacademy.auth.token.RefreshToken;
import com.nhnacademy.auth.exception.AuthenticationFailedException;
import com.nhnacademy.auth.provider.JwtTokenProvider;
import com.nhnacademy.auth.repository.RefreshTokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 사용자가 /login을 요청하면 UsernamePasswordAuthenticationFilter가 요청을 가로챔
 * request에서 username&password를 꺼내서 Authentication 객체로 만듦. 우리는 jwt로 인증해야 하므로 JwtAuthenticationFilter를 새로 만듦.
 * UsernamePasswordAuthenticationFilter의 특징으론
 * 인증 요청이 성공/실패 했을 때 별도로 처리하는 로직인 successfulAuthentication, unsuccessfulAuthentication이 실행됨. 그래서 후처리를 위해 구현해야함.
 * 해당 필터는 /login에 접근할 때만 동작한다. => 그렇기 때문에 내가 원하는 Url에서 필터가 동작하길 원한다면 setFilterProcessesUrl()로 Url를 설정해줘야 작동한다.
 */
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    /**
     *  redis key 값에 추가할 prefix.
     */
    @Value("${token.prefix}")
    private String tokenPrefix;

    /**
     * 로그 lombok 이 되지 않아 사용.
     */
    private final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    /**
     * JWT token 발급 후 저장하는 repository.
     */
    private final RefreshTokenRepository refreshTokenRepository;

    /**
     * custom한 MemberDetail 및 service를 넣어주기 위한 authenticationManager.
     */
    private final AuthenticationManager authenticationManager;

    /**
     * Jwt 발급하는 provider.
     */
    private final JwtTokenProvider jwtTokenProvider;

    /**
     *  request 에서 받아온 요청값을 json형태로 바꿀 objectMapper.
     */
    private final ObjectMapper objectMapper;


    public JwtAuthenticationFilter(RefreshTokenRepository refreshTokenRepository, AuthenticationManager authenticationManager,
                                   JwtTokenProvider jwtTokenProvider, ObjectMapper objectMapper) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
        this.objectMapper = objectMapper;
        setFilterProcessesUrl("/auth/login");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info("---USERNAME&PASSWORD_FILTER_BY_JWT---");
        try {
            //request 요청 값에서 id, password가 있어야 함. 그걸 loginRequest.class로 받아올 수 있어야함...
            LoginRequest loginRequest = objectMapper.readValue(request.getInputStream(), LoginRequest.class);
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                    loginRequest.getMemberEmail(),
                    loginRequest.getMemberPassword()
            );
            return authenticationManager.authenticate(usernamePasswordAuthenticationToken);

        } catch (Exception e) {
            throw new AuthenticationFailedException (e.getMessage());
        }
    }

    //인증 성공 후 jwt 반환
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        MemberDetails memberDetails = (MemberDetails) authResult.getPrincipal();

        List<String> authorities = memberDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        String role = authorities.isEmpty() ? null : authorities.getFirst();

        JwtTokenDto jwtTokenDto = jwtTokenProvider.generateTokenDto(authResult.getName(), role);
        String redisKey = DigestUtils.sha256Hex(tokenPrefix + ":" + authResult.getName());
        refreshTokenRepository.save(new RefreshToken(redisKey, jwtTokenDto.getRefreshToken()));
        String result = objectMapper.writeValueAsString(jwtTokenDto);

        //로그인 성공 이벤트 발생 -> 최근 로그인 시간 업데이트
        ApplicationContextHolder.getContext().getBean(ApplicationEventPublisher.class).publishEvent(new LoginSuccessEvent(this, authResult.getName()));

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(result);
        response.getWriter().flush();
    }

    //인증 실패. 실패 json 반환.
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        // 실패 응답 구성
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("timestamp", System.currentTimeMillis());
        errorResponse.put("status", HttpServletResponse.SC_UNAUTHORIZED); // 401
        errorResponse.put("error", "Unauthorized");
        errorResponse.put("message", failed.getMessage()); // 예외 메시지
        errorResponse.put("path", request.getRequestURI());

        // 응답 설정
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        // JSON으로 변환해서 응답
        String json = objectMapper.writeValueAsString(errorResponse);
        response.getWriter().write(json);
        response.getWriter().flush();
    }
}
