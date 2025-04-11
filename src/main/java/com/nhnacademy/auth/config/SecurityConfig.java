package com.nhnacademy.auth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nhnacademy.auth.filter.JwtAuthenticationFilter;
import com.nhnacademy.auth.provider.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity(debug = true)
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
                                    "/auth/signup",
                                    "/auth/register",
                                    "/api/auth/register",
                                    "api/auth/login"
                            ).permitAll()
                            .anyRequest().authenticated(); // 나머지 요청은 인증이 필요
                })
//                .cors(Customizer.withDefaults())
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterAt(jwtAuthenticationFilter
                                (http.getSharedObject(AuthenticationManager.class)),
                        UsernamePasswordAuthenticationFilter.class);

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
    public AuthenticationManager authenticationManager
    (AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     * JWT 인증 필터 빈 등록.
     * @param authenticationManager securityConfig에서 생성되는 manager
     * @return JwtAuthenticationFilter
     * @throws Exception 예외 발생 시
     */
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter
    (AuthenticationManager authenticationManager) {
        JwtAuthenticationFilter filter =
                new JwtAuthenticationFilter(authenticationManager,
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

//    @Bean
//    public CorsConfigurationSource corsConfigurationSource() {
//        CorsConfiguration configuration = new CorsConfiguration();
//        configuration.setAllowedOrigins(List.of("http://localhost:10251")); // 허용할 Origin
//        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
//        configuration.setAllowedHeaders(List.of("*")); // 모든 헤더 허용
//        configuration.setAllowCredentials(true); // 쿠키 허용 시 true
//
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/**", configuration); // 모든 경로에 적용
//        return source;
//    }

}
