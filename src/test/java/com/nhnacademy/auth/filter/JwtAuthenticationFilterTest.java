package com.nhnacademy.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nhnacademy.auth.AuthApplication;
import com.nhnacademy.auth.detail.MemberDetails;
import com.nhnacademy.auth.exception.AttemptAuthenticationFailedException;
import com.nhnacademy.auth.member.request.LoginRequest;
import com.nhnacademy.auth.member.response.MemberLoginResponse;
import com.nhnacademy.auth.provider.JwtTokenProvider;
import com.nhnacademy.auth.repository.RefreshTokenRepository;
import com.nhnacademy.auth.token.JwtTokenDto;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
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
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.DelegatingServletInputStream;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import com.nhnacademy.auth.context.ApplicationContextHolder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Collections;

@SpringBootTest(classes = AuthApplication.class)
@ExtendWith(MockitoExtension.class)
@Slf4j
class JwtAuthenticationFilterTest {

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

    private ObjectMapper objectMapper = new ObjectMapper();

    private Authentication authentication;

    @BeforeEach
    void setUp() {
        authentication = Mockito.mock(Authentication.class);
        ReflectionTestUtils.setField(jwtAuthenticationFilter, "tokenPrefix", "Bearer");
    }

    @Test
    @DisplayName("로그인 시도.")
    void attemptAuthentication() throws IOException {
        String id = "test@test.com";
        String password = "password";

        LoginRequest loginRequest = new LoginRequest(id, password);
        String json = objectMapper.writeValueAsString(loginRequest);
        InputStream inputStream = new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8));
        BDDMockito.given(request.getInputStream()).willReturn(new DelegatingServletInputStream(inputStream));

        jwtAuthenticationFilter = new JwtAuthenticationFilter(refreshTokenRepository, authenticationManager, jwtTokenProvider, objectMapper);

        BDDMockito.given(authenticationManager.authenticate(Mockito.any(UsernamePasswordAuthenticationToken.class)))
                .willReturn(authentication);

        Authentication result = jwtAuthenticationFilter.attemptAuthentication(request, response);

        Assertions.assertNotNull(result);
    }

    @Test
    @DisplayName("로그인 시도 실패 시 예외 발생")
    void attemptAuthenticationFailed() throws Exception {
        // IOException 발생하는 InputStream 세팅
        ServletInputStream inputStream = new ServletInputStream() {
            @Override
            public int read() throws IOException {
                throw new IOException("Test IOException");
            }

            @Override
            public boolean isFinished() { return false; }
            @Override
            public boolean isReady() { return true; }
            @Override
            public void setReadListener(ReadListener listener) { /* TODO document why this method is empty */ }
        };

        BDDMockito.given(request.getInputStream()).willReturn(inputStream);

        Assertions.assertThrows(AttemptAuthenticationFailedException.class, () ->
                jwtAuthenticationFilter.attemptAuthentication(request, response));
    }

    @Test
    @DisplayName("attemptAuthentication에서 Json 파싱 실패 시")
    void attemptAuthentication_throwsAuthenticationFailedException_invalidJson() throws IOException {
        request = Mockito.mock(HttpServletRequest.class);
        response = Mockito.mock(HttpServletResponse.class);
        Mockito.when(request.getInputStream()).thenThrow(new IOException("invalid json"));

        Assertions.assertThrows(AttemptAuthenticationFailedException.class, () ->{
            jwtAuthenticationFilter.attemptAuthentication(request, response);
        });
    }

    @Test
    @DisplayName("로그인 성공 시.")
    void successfulAuthentication() throws Exception {
        //1. Filter 내부에서 JwtTokenProvider 호출 시 설정한 jwtTokenDto를 반환하도록 설정.
        JwtTokenDto jwtTokenDto = new JwtTokenDto("accessToken", "refreshToken");
        BDDMockito.given(jwtTokenProvider.generateTokenDto(Mockito.anyString(), Mockito.anyString()))
                .willReturn(jwtTokenDto);

        //2. (1)을 위해서 jwtAuthenticationFilter를 새로 생성해서 jwtTokenProvider 를 삽입.
        jwtAuthenticationFilter = new JwtAuthenticationFilter(refreshTokenRepository, authenticationManager, jwtTokenProvider, objectMapper);

        // 오타 방지를 위한 회원 정보.
        Long memberNo = 1L;
        String memberEmail = "test@test.com";
        String memberPassword = "password";
        String roleId = "ROLE_USER";

        // 로그인 되었을 때 MemberDetails에 넣을 memberLoginResponse 값.
        MemberLoginResponse memberLoginResponse = new MemberLoginResponse(
                memberNo, memberEmail, memberPassword, roleId);

        // 3. memberDetails가 memberLoginResponse를 필요로 하므로 넣어줌. 원래라면 memberDetailsService가 memberadaptor에서 id(=email)값으로
        //      받아오는 정보를 통해 memberDetails를 새로 생성하지만 테스트이므로 직접 넣어줌.
        MemberDetails memberDetails = new MemberDetails(memberLoginResponse);

        // 4. 로그인 시도 시 생성하는 UsernamePasswordAuthenticationToken 생성.
        Authentication auth = new UsernamePasswordAuthenticationToken(memberDetails, memberPassword, memberDetails.getAuthorities());

        log.info("auth getPrincipal: {}", auth.getPrincipal());

        // 5. ApplicationContextHolder 세팅 (LoginSuccessEvent 때문에)
        ApplicationContext mockContext = Mockito.mock(ApplicationContext.class);
        ApplicationEventPublisher mockPublisher = Mockito.mock(ApplicationEventPublisher.class);
        Mockito.when(mockContext.getBean(ApplicationEventPublisher.class)).thenReturn(mockPublisher);
        ApplicationContextHolder.setContext(mockContext);

        // 6. success후 response의 getWriter를 호출하기 때문에 가상 객체라 Writer가 없는 response에 생성해서 넣어줌.
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(outputStream, StandardCharsets.UTF_8), true);
        Mockito.when(response.getWriter()).thenReturn(printWriter);

        // 7. 대망의 테스트할 거 호출
        jwtAuthenticationFilter.successfulAuthentication(request, response, filterChain, auth);

        //결과 검증
        String expectedResponse = objectMapper.writeValueAsString(jwtTokenDto);
        log.info("expectedResponse: {}", expectedResponse);
        Assertions.assertEquals(expectedResponse, outputStream.toString());
    }

    @Test
    @DisplayName("로그인 성공 시 권한이 없는 경우")
    void successfulAuthenticationWithoutAuthorities() throws Exception {
        // given
        JwtTokenDto jwtTokenDto = new JwtTokenDto("accessToken", "refreshToken");
        BDDMockito.given(jwtTokenProvider.generateTokenDto(Mockito.any(), Mockito.any()))
                .willReturn(jwtTokenDto);

        jwtAuthenticationFilter = new JwtAuthenticationFilter(refreshTokenRepository, authenticationManager, jwtTokenProvider, objectMapper);

        Long memberNo = 1L;
        String memberEmail = "noauth@test.com";
        String memberPassword = "password";
        String roleId = null;

        // 권한 없이 생성
        MemberLoginResponse memberLoginResponse = new MemberLoginResponse(
                memberNo, memberEmail, memberPassword, roleId);

        MemberDetails memberDetails = new MemberDetails(memberLoginResponse) {
            @Override
            public Collection<? extends GrantedAuthority> getAuthorities() {
                return Collections.emptyList(); // 권한 없음
            }
        };

        Authentication auth = new UsernamePasswordAuthenticationToken(memberDetails, memberPassword, memberDetails.getAuthorities());

        ApplicationContext mockContext = Mockito.mock(ApplicationContext.class);
        ApplicationEventPublisher mockPublisher = Mockito.mock(ApplicationEventPublisher.class);
        Mockito.when(mockContext.getBean(ApplicationEventPublisher.class)).thenReturn(mockPublisher);
        ApplicationContextHolder.setContext(mockContext);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(outputStream, StandardCharsets.UTF_8), true);
        Mockito.when(response.getWriter()).thenReturn(printWriter);

        // when
        jwtAuthenticationFilter.successfulAuthentication(request, response, filterChain, auth);

        // then
        String expectedResponse = objectMapper.writeValueAsString(jwtTokenDto);
        Assertions.assertEquals(expectedResponse, outputStream.toString());
    }


    @Test
    @DisplayName("로그인 실패 시.")
    void unsuccessfulAuthentication() throws ServletException, IOException {
        jwtAuthenticationFilter = new JwtAuthenticationFilter(refreshTokenRepository, authenticationManager, jwtTokenProvider, objectMapper);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(outputStream, StandardCharsets.UTF_8), true);
        Mockito.when(response.getWriter()).thenReturn(printWriter);

        // request.getRequestURI() 세팅
        Mockito.when(request.getRequestURI()).thenReturn("/auth/login");

        // 실패 메서드 호출
        AuthenticationException failed = Mockito.mock(AuthenticationException.class);
        jwtAuthenticationFilter.unsuccessfulAuthentication(request, response, failed);

        // 5. 결과 검증
        String responseBody = outputStream.toString();
        log.info("responseBody: {}", responseBody);
        Assertions.assertNotNull(responseBody);
        Assertions.assertTrue(responseBody.contains("/auth/login"));

        // 6. response 401 status 설정했는지 검증
        Mockito.verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }


}
