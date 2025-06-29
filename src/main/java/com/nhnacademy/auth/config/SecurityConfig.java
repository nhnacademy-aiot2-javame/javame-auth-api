package com.nhnacademy.auth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nhnacademy.auth.exception.entrypoint.CustomAuthenticationEntryPoint;
import com.nhnacademy.auth.filter.CustomHeaderAuthenticationFilter;
import com.nhnacademy.auth.filter.JwtAuthenticationFilter;
import com.nhnacademy.auth.member.adaptor.MemberAdaptor;
import com.nhnacademy.auth.provider.JwtTokenProvider;
import com.nhnacademy.auth.repository.RefreshTokenRepository;
import com.nhnacademy.auth.detail.MemberDetailsService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableAsync
@Configuration
@EnableWebSecurity()
public class SecurityConfig {
    /**
     * JWT 토큰을 생성, 파싱 및 검증하는 유틸리티 클래스입니다.
     * Access Token 및 Refresh Token의 생성과 유효성 검사를 담당합니다.
     */
    @Value("${jwt.secret}")
    private String key;

    /**
     * SecurityConfig 생성자입니다.
     *
     * @param key JWT 토큰 유틸리티
     */

    /**
     * Spring Security의 필터 체인을 정의합니다.
     * csrf보호 기능 해제, 디폴트 로그인, 로그아웃 폼 사용 해제, 세션을 stateless로 설정합니다.
     * jwtAuthenticationFilter가 기존 UsernamePasswordAuthenticationFilter 필터 자리를 차지해 작동될 수 있도록 합니다.
     *
     * @param http HttpSecurity
     * @param refreshTokenRepository refresh token 저장소
     * @param customAuthenticationEntryPoint 인증 에러 처리를 ExceptionHandler에서 처리할 수 있도록 설정한 custom entry point
     * @param customHeaderAuthenticationFilter X-User-Role, X-User-Email을 SecurityContextHolder에 넣는 필터.
     * @return SecurityFilterChain
     * @throws Exception 예외 발생 시
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, RefreshTokenRepository refreshTokenRepository,
                                           CustomHeaderAuthenticationFilter customHeaderAuthenticationFilter,
                                           CustomAuthenticationEntryPoint customAuthenticationEntryPoint) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(requests -> {
                    requests
                            .requestMatchers(
                                    "/test/**",
                                    "/auth/register-owner",
                                    "/auth/register",
                                    "/auth/purchase",
                                    "/api/v1/auth/login",
                                    "/auth/login",
                                    "/auth/signup",
                                    "/v3/api-docs/**",
                                    "/swagger-ui/**",
                                    "/swagger-ui.html",
                                    "/error",
                                    "/favicon.ico"
                            )
                            .permitAll()
                            .anyRequest().authenticated(); // 나머지 요청은 인증이 필요
                })
                .exceptionHandling(handler -> handler.authenticationEntryPoint(customAuthenticationEntryPoint))
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(customHeaderAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAt(jwtAuthenticationFilter
                                (http.getSharedObject(AuthenticationManager.class), refreshTokenRepository),
                        UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * 인증 매니저 빈 등록.
     *
     * @param memberDetailsService custom 한 memberDetailsService
     * @param passwordEncoder bCryptPasswordEncoder
     * @return AuthenticationManager
     * @throws Exception 예외 발생 시
     */
    @Bean
    public AuthenticationManager authenticationManager (MemberDetailsService memberDetailsService, PasswordEncoder passwordEncoder) throws Exception {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(memberDetailsService);
        provider.setPasswordEncoder(passwordEncoder);

        return new ProviderManager(provider);
    }

    @Bean
    public MemberDetailsService memberDetailsService(MemberAdaptor memberAdaptor) {
        return new MemberDetailsService(memberAdaptor);
    }

    /**
     * JWT 인증 필터 빈 등록.
     * @param authenticationManager securityConfig에서 생성되는 manager
     * @param refreshTokenRepository JWT refresh token 저장 및 조회하는 repository
     * @return JwtAuthenticationFilter
     */
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter
    (AuthenticationManager authenticationManager, RefreshTokenRepository refreshTokenRepository) {
        JwtAuthenticationFilter filter =
                new JwtAuthenticationFilter(refreshTokenRepository,
                        authenticationManager,
                        jwtTokenProvider(),
                        objectMapper());
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }

    /**
     * JWT 토큰 제공자 빈 등록.
     * @return JwtTokenProvider
     */
    @Bean
    public JwtTokenProvider jwtTokenProvider() {
        return new JwtTokenProvider(key);
    }

    /**
     * ObjectMapper 빈 등록.
     *
     * @return ObjectMapper
     */
    @Bean
    public ObjectMapper objectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        return objectMapper;
    }

    /**
     * 비밀번호 인코더 빈 등록.
     *
     * @return PasswordEncoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
