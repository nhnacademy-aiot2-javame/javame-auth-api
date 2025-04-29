package com.nhnacademy.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nhnacademy.auth.AuthApplication;
import com.nhnacademy.auth.detail.MemberDetails;
import com.nhnacademy.auth.exception.AuthenticationFailedException;
import com.nhnacademy.auth.member.request.LoginRequest;
import com.nhnacademy.auth.member.response.MemberLoginResponse;
import com.nhnacademy.auth.provider.JwtTokenProvider;
import com.nhnacademy.auth.repository.RefreshTokenRepository;
import com.nhnacademy.auth.token.JwtTokenDto;
import com.nhnacademy.auth.token.RefreshToken;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.DelegatingServletInputStream;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@SpringBootTest(classes = AuthApplication.class)
@ExtendWith(MockitoExtension.class)
@Slf4j
class JwtAuthenticationFilterTest {

    @Mock
    private PasswordEncoder passwordEncoder;

    private ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    private FilterChain filterChain;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @Mock
    private AuthenticationManager authenticationManager;

    @InjectMocks
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private Authentication authentication = Mockito.mock(Authentication.class);;

    @BeforeEach
    void setUp() throws Exception {
        String id = "test@test.com";
        String password = "password";

        authentication = Mockito.mock(Authentication.class);
        jwtAuthenticationFilter = new JwtAuthenticationFilter(refreshTokenRepository, authenticationManager, jwtTokenProvider, objectMapper);
        authentication = new UsernamePasswordAuthenticationToken(id, password);

        log.info("authentication = {}", authentication);

        LoginRequest loginRequest = new LoginRequest(id, password);
        log.info("loginRequest: {}", loginRequest);
        String json = objectMapper.writeValueAsString(loginRequest);
        log.info("json: {}", json);

        InputStream inputStream = new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8));
        BDDMockito.given(request.getInputStream()).willReturn(new DelegatingServletInputStream(inputStream));
    }

    @Test
    @DisplayName("로그인 시도.")
    void attemptAuthentication() {
        BDDMockito.given(authenticationManager.authenticate(Mockito.any(UsernamePasswordAuthenticationToken.class))).willReturn(authentication);
        Authentication result = jwtAuthenticationFilter.attemptAuthentication(request, response);
        Assertions.assertNotNull(result);
    }

    @Test
    @DisplayName("로그인 시도에서 request값을 못 받아왔을 때 Exception 발생 처리")
    void attemptAuthenticationFailed() throws IOException {
        ServletInputStream inputStream = new ServletInputStream() {
            @Override
            public int read() throws IOException {
                throw new IOException("Test IOException");
            }

            @Override
            public boolean isFinished() {
                return false;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener readListener) {
            }
        };

        BDDMockito.given(request.getInputStream()).willReturn(inputStream);
        Assertions.assertThrows(AuthenticationFailedException.class, () ->
                jwtAuthenticationFilter.attemptAuthentication(request, response));
    }

    @Test
    @DisplayName("로그인 성공 시.")
    void successfulAuthentication() throws Exception {
        // member 정보 mock 설정
        Long memberNo = 1L;
        String memberEmail = "test@test.com";
        String memberPassword = "password";
        String roleId = "ROLE_USER";
        MemberLoginResponse loginResponse = new MemberLoginResponse(memberNo, memberEmail, memberPassword, roleId);
        MemberDetails memberDetails = Mockito.mock(MemberDetails.class);
        Mockito.doReturn(Collections.singletonList(new SimpleGrantedAuthority(response.getRoleId()))).when(memberDetails.getAuthorities());

        // getAuthorities() 메서드를 mock하여 권한 리스트 반환

        Mockito.doReturn(Collections.singletonList(new SimpleGrantedAuthority(loginResponse.getRoleId()))).when(memberDetails.getAuthorities());



        // authentication 객체를 mock하고, principal로 memberDetails 설정
        BDDMockito.given(authentication.getPrincipal()).willReturn(memberDetails);
        BDDMockito.given(authentication.getName()).willReturn(memberEmail);

        // JWT 토큰 생성 모킹
        JwtTokenDto jwtTokenDto = new JwtTokenDto("accessToken", "refreshToken");
        BDDMockito.given(jwtTokenProvider.generateTokenDto(Mockito.anyString(), Mockito.anyString()))
                .willReturn(jwtTokenDto);

        // Redis key 생성 모킹
        String redisKey = "test:redisKey";
        BDDMockito.given(DigestUtils.sha256Hex("test:someKey")).willReturn(redisKey);

        // ByteArrayOutputStream과 ServletOutputStream을 mock하여 response를 처리
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        ServletOutputStream servletOutputStream = new ServletOutputStream() {
            @Override
            public void write(int b) {
                outputStream.write(b);
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setWriteListener(WriteListener writeListener) {
            }
        };

        // response.getOutputStream()을 mock
        Mockito.when(response.getOutputStream()).thenReturn(servletOutputStream);

        // Act
        jwtAuthenticationFilter.successfulAuthentication(request, response, filterChain, authentication);

        // MemberLoginResponse 객체 생성
        MemberLoginResponse memberLoginResponse = new MemberLoginResponse(
                memberNo, memberEmail, memberPassword, roleId);

        // 예상 응답을 JSON으로 변환
        String expectedResponse = objectMapper.writeValueAsString(memberLoginResponse);

        // Assert
        Assertions.assertEquals(expectedResponse, outputStream.toString());
    }

    @Test
    @DisplayName("로그인 실패 시.")
    void unsuccessfulAuthentication() {
    }
}