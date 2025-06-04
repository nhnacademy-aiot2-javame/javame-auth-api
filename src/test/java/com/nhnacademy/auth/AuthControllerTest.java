package com.nhnacademy.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nhnacademy.auth.company.adaptor.CompanyAdaptor;
import com.nhnacademy.auth.company.request.CompanyUpdateEmailRequest;
import com.nhnacademy.auth.config.SecurityConfig;
import com.nhnacademy.auth.exception.entrypoint.CustomAuthenticationEntryPoint;
import com.nhnacademy.auth.member.adaptor.MemberAdaptor;
import com.nhnacademy.auth.member.request.MemberPasswordChangeRequest;
import com.nhnacademy.auth.member.request.MemberRegisterRequest;
import com.nhnacademy.auth.member.response.MemberResponse;
import com.nhnacademy.auth.provider.JwtTokenProvider;
import com.nhnacademy.auth.repository.RefreshTokenRepository;
import com.nhnacademy.auth.token.JwtTokenDto;
import com.nhnacademy.auth.token.RefreshToken;
import jakarta.servlet.http.Cookie;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.file.AccessDeniedException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@Slf4j
@WebMvcTest(
        controllers = AuthController.class,
        excludeAutoConfiguration = SecurityAutoConfiguration.class,
        excludeFilters = {
                @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE, classes = SecurityConfig.class)
        }
        )
@Import(SecurityConfig.class)
@ExtendWith(MockitoExtension.class)
@AutoConfigureMockMvc(addFilters = false)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private CompanyAdaptor companyAdaptor;

    @MockitoBean
    private MemberAdaptor memberAdaptor;

    @MockitoBean
    private PasswordEncoder passwordEncoder;

    @MockitoBean
    private RefreshTokenRepository refreshTokenRepository;

    @MockitoBean
    private CustomAuthenticationEntryPoint customAuthenticationEntryPoint;


    private String testEmail = "test@test.com";

    private String testPassword = "testPassword1!";

    private String testDomain = "test.com";

    private String testToken = "test.jwt.token";

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    JwtTokenProvider jwtTokenProvider;

    @BeforeEach
    void setUp() {
        // Authentication 객체를 수동으로 설정 (로그인된 사용자 세팅)
        User principal = new User(testEmail, testPassword, new ArrayList<>());
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
    }

    @Test
    @DisplayName("회원 가입 테스트 후 메세지 주는지 검증.")
    void signUp() throws Exception {
        MemberRegisterRequest registerRequest = new MemberRegisterRequest(testEmail, testPassword, testDomain);
        String json = objectMapper.writeValueAsString(registerRequest);

        MemberResponse memberResponse = new MemberResponse(1L, testEmail, testDomain, "ROLE_USER", LocalDateTime.now(), LocalDateTime.now());

        Mockito.when(memberAdaptor.registerMember(Mockito.any(MemberRegisterRequest.class)))
                .thenReturn(ResponseEntity.ok().body(memberResponse));

        mockMvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.message").value("회원가입 성공"))
                .andDo(print());
    }

    @Test
    @DisplayName("오너 회원 가입 테스트 후 검증.")
    void signUp_owner() throws Exception {
        MemberRegisterRequest registerRequest = new MemberRegisterRequest(testEmail, testPassword, testDomain);
        String json = objectMapper.writeValueAsString(registerRequest);
        MemberResponse memberResponse = new MemberResponse(1L, testEmail, testDomain, "ROLE_OWNER", LocalDateTime.now(), LocalDateTime.now());

        Mockito.when(memberAdaptor.registerOwner(Mockito.any(MemberRegisterRequest.class)))
                .thenReturn(ResponseEntity.ok().body(memberResponse));

        mockMvc.perform(post("/auth/register-owner")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.message").value("회원가입 성공"))
                .andDo(print());
    }

    @Test
    @DisplayName("로그아웃 시 쿠키 값을 비우는지 검증.")
    void logout() throws Exception {
        MvcResult result = mockMvc.perform(post("/auth/logout")
                        .cookie(new Cookie("refreshToken", testToken))
                        .cookie(new Cookie("accessToken", testToken)))
                .andExpect(status().isOk()).andReturn();

        List<String> header = result.getResponse().getHeaders("Set-Cookie");
        log.info("result response: {}", header);

        // Check if deleteById was called with the correct token
        Mockito.verify(refreshTokenRepository, Mockito.times(1)).deleteById(Mockito.anyString());
        Assertions.assertNotNull(header);
        Assertions.assertTrue(header.stream().anyMatch(h -> h.startsWith("accessToken=;") && h.contains("Max-Age=0")));
        Assertions.assertTrue(header.stream().anyMatch(h -> h.startsWith("refreshToken=;") && h.contains("Max-Age=0")));
    }

    @Test
    @DisplayName("refresh 토큰으로 jwt 토큰 새로 발급 성공.")
    void refreshSuccessTest() throws Exception {
        Mockito.when(jwtTokenProvider.generateTokenDto(testEmail, "ROLE_USER")).thenReturn(new JwtTokenDto(testToken, testToken));
        Mockito.when(refreshTokenRepository.existsById(Mockito.anyString())).thenReturn(true);
        Mockito.when(jwtTokenProvider.getUserEmailFromToken(Mockito.anyString())).thenReturn(testEmail);
        Mockito.when(jwtTokenProvider.getRoleIdFromToken(Mockito.anyString())).thenReturn("ROLE_USER");
        MockCookie testCookie = new MockCookie("refreshToken", testToken);

        MvcResult result = mockMvc.perform(get("/auth/refresh")
                        .with(mockHttpServletRequest -> {
                            mockHttpServletRequest.setCookies(testCookie);
                            return mockHttpServletRequest;
                        })
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn();

        String resultString = result.getResponse().getContentAsString();

        Mockito.verify(refreshTokenRepository, Mockito.times(1)).existsById(Mockito.anyString());
        Mockito.verify(refreshTokenRepository, Mockito.times(1)).save(Mockito.any(RefreshToken.class));
        Assertions.assertTrue(resultString.contains(testToken));

        log.info("resultString: {}", resultString);
    }

    @Test
    @DisplayName("refresh 토큰으로 jwt 토큰 새로 발급 실패했을 때 null이 나오는지 테스트.")
    void refreshFailedTest() throws Exception {
        Mockito.when(jwtTokenProvider.getUserEmailFromToken(Mockito.anyString())).thenReturn(testEmail);
        Mockito.when(jwtTokenProvider.getRoleIdFromToken(Mockito.anyString())).thenReturn("ROLE_USER");
        Mockito.when(refreshTokenRepository.existsById(Mockito.anyString())).thenReturn(false); // 존재하지 않는다고 설정

        MockCookie testCookie = new MockCookie("refreshToken", testToken);

        MvcResult result = mockMvc.perform(get("/auth/refresh")
                        .with(mockHttpServletRequest -> {
                            mockHttpServletRequest.setCookies(testCookie);
                            return mockHttpServletRequest;
                        })
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn();

        String resultString = result.getResponse().getContentAsString();

        Assertions.assertEquals("", resultString);

        log.info("resultString: {}", resultString);
    }

    @Test
    @DisplayName("비밀번호 변경 시 토큰이 changeMemberPassword가 호출되는지 확인")
    void updatePassword() throws Exception {
        String encodeTestPassword = "encodePassword";
        MemberResponse memberResponse = new MemberResponse(1L, testEmail, "test.com", "ROLE_USER", LocalDateTime.now(), LocalDateTime.now());
        Mockito.when(jwtTokenProvider.getUserEmailFromToken(Mockito.anyString())).thenReturn(testEmail);
        Mockito.when(memberAdaptor.getMemberByEmail(Mockito.anyString())).thenReturn(ResponseEntity.ok(memberResponse));
        MemberPasswordChangeRequest rq = new MemberPasswordChangeRequest(testPassword, encodeTestPassword);
        Mockito.when(memberAdaptor.changeMemberPassword(memberResponse.getMemberNo(), rq, memberResponse.getMemberEmail())).thenReturn(ResponseEntity.ok().build());

        mockMvc.perform(patch("/auth/update/password")
                        .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(rq)))
                .andExpect(status().isOk())
                .andReturn();

        Mockito.verify(memberAdaptor, Mockito.times(1)).changeMemberPassword(Mockito.anyLong(), Mockito.any(MemberPasswordChangeRequest.class), Mockito.any());
    }

    @Test
    @DisplayName("Onwer의 아이디이자, 회사 대표 이메일을 변경할 때 성공시")
    void updateEmailSuccess() throws Exception {
        String newEmail = "new@email.com";

        CompanyUpdateEmailRequest request = new CompanyUpdateEmailRequest(testEmail, newEmail);

        Mockito.when(jwtTokenProvider.getRoleIdFromToken(Mockito.anyString())).thenReturn("ROLE_OWNER");

        mockMvc.perform(patch("/auth/update/{companyDomain}/email", testDomain)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andReturn();

        Mockito.verify(companyAdaptor, Mockito.times(1))
                .updateCompanyEmail(Mockito.eq(testDomain), Mockito.any(CompanyUpdateEmailRequest.class));

    }

    @Test
    @DisplayName("인증된 사용자와 요청한 이메일이 다른 경우.")
    void updateEmailFailedByEmailNotEquals() {
        String newEmail = "new@email.com";
        String wrongEmail = "wrong@email.com";

        CompanyUpdateEmailRequest request = new CompanyUpdateEmailRequest(wrongEmail, newEmail);

        Mockito.when(jwtTokenProvider.getRoleIdFromToken(Mockito.anyString())).thenReturn("ROLE_OWNER");

        AccessDeniedException exception = Assertions.assertThrows(AccessDeniedException.class, () -> {
            mockMvc.perform(patch("/auth/update/{companyDomain}/email", testDomain)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isForbidden())
                    .andReturn();
        });

        // 예외 메시지 확인
        Assertions.assertEquals("인증된 사용자와 요청한 이메일이 일치하지 않습니다.", exception.getMessage());
    }

    @Test
    @DisplayName("업데이트 권한이 없는 경우. ")
    void updateEmailFailedByRole() {
        String newEmail = "new@email.com";

        CompanyUpdateEmailRequest request = new CompanyUpdateEmailRequest(testEmail, newEmail);

        Mockito.when(jwtTokenProvider.getRoleIdFromToken(Mockito.anyString())).thenReturn("ROLE_USER");

        AccessDeniedException exception = Assertions.assertThrows(AccessDeniedException.class, () -> {
            mockMvc.perform(patch("/auth/update/{companyDomain}/email", testDomain)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isForbidden())
                    .andReturn();
        });

        Assertions.assertEquals("이메일 변경 권한이 없습니다.", exception.getMessage());
    }
}
