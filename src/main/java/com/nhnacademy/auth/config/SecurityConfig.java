package com.nhnacademy.auth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nhnacademy.auth.filter.JwtAuthenticationFilter;
import com.nhnacademy.auth.provider.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity(debug = true)
public class SecurityConfig {

    /**
     * Spring Security에서 제공하는 인증 처리 매니저로,
     * 사용자의 인증 정보를 검증하는 역할을 수행합니다.
     */
    private final AuthenticationManager authenticationManager;

    /**
     * JWT 인증 필터로, 요청에서 JWT 토큰을 추출하고
     * 유효성을 검사하여 인증 정보를 설정합니다.
     */
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    /**
     * JWT 토큰을 생성, 파싱 및 검증하는 유틸리티 클래스입니다.
     * Access Token 및 Refresh Token의 생성과 유효성 검사를 담당합니다.
     */
    private final JwtTokenProvider jwtTokenProvider;

    /**
     * SecurityConfig 생성자입니다.
     *
     * @param authenticationManager 인증 관리자
     * @param jwtAuthenticationFilter JWT 인증 필터
     * @param jwtTokenProvider JWT 토큰 유틸리티
     */
    public SecurityConfig(AuthenticationManager authenticationManager,
                          JwtAuthenticationFilter jwtAuthenticationFilter,
                          JwtTokenProvider jwtTokenProvider) {
        this.authenticationManager = authenticationManager;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    /**
     * Spring Security의 필터 체인을 정의합니다.
     *
     * @param http HttpSecurity
     * @return SecurityFilterChain
     * @throws Exception 예외 발생 시
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(requests -> {
                    requests
                            .requestMatchers(
                                    "/auth/login",
                                    "/auth/signup"
                            ).permitAll()
                            .anyRequest().authenticated(); // 나머지 요청은 인증이 필요
                })
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Session 없이 JWT로 인증
                .addFilterAt(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * 인증 매니저 빈 등록.
     *
     * @param authenticationConfiguration 인증 설정
     * @return AuthenticationManager
     * @throws Exception 예외 발생 시
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     * JWT 인증 필터 빈 등록.
     *
     * @return JwtAuthenticationFilter
     * @throws Exception 예외 발생 시
     */
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() throws Exception {
        JwtAuthenticationFilter filter =
                new JwtAuthenticationFilter(authenticationManager, jwtTokenProvider, objectMapper());
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }

    /**
     * JWT 토큰 제공자 빈 등록.
     *
     * @param secretKey 시크릿 키
     * @return JwtTokenProvider
     */
    @Bean
    public JwtTokenProvider jwtTokenProvider(@Value("${jwt.secret}") String secretKey) {
        return new JwtTokenProvider(secretKey);
    }

    /**
     * ObjectMapper 빈 등록.
     *
     * @return ObjectMapper
     */
    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
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
