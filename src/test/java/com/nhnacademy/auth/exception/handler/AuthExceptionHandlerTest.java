package com.nhnacademy.auth.exception.handler;

import com.nhnacademy.auth.exception.controller.ExceptionTestController;
import com.nhnacademy.auth.exception.entrypoint.CustomAuthenticationEntryPoint;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Slf4j
class AuthExceptionHandlerTest {

    @Autowired
    MockMvc mockMvc;

    @Test
    @DisplayName("로그인 시도 실패 시 설정한 ErrorResponse 반환 체크 ")
    void attemptAuthenticationException() throws Exception {
        MvcResult mvcResult = mockMvc.perform(get("/test/login-failed"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.error").value("Unauthorized"))
                .andExpect(jsonPath("$.message").value("Username and Password not accepted"))
                .andReturn();

        log.info("result: {}", mvcResult.getResponse().getContentAsString());
    }

    @Test
    @DisplayName("로그인 시도 실패 시 설정한 ErrorResponse 반환 체크 -by 메세지 ")
    void attemptAuthenticationException_2() throws Exception {
        MvcResult mvcResult = mockMvc.perform(get("/test/login-failed/message"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.error").value("Unauthorized"))
                .andExpect(jsonPath("$.message").value("message"))
                .andReturn();

        log.info("result: {}", mvcResult.getResponse().getContentAsString());
    }

    @Test
    @DisplayName("JwtTokenDto generateTokenDto 시 String userEmail, roll가 null일 때 ")
    void tokenDtoGenerateFailedException() throws Exception {
        MvcResult mvcResult = mockMvc.perform(get("/test/token-failed"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value("test is empty."))
                .andReturn();

        log.info("result: {}", mvcResult.getResponse().getContentAsString());
    }

    @Test
    @DisplayName("getUserEmailFromToken 에서 accessToken이 Empty일 때")
    void tokenMissingException_1() throws Exception {
        mockMvc.perform(get("/test/token-missing"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.error").value("Unauthorized"))
                .andExpect(jsonPath("$.message").value("test is missing from the request."))
                .andDo(print())
                .andReturn();
    }

    @Test
    @DisplayName("쿠키에서 토큰을 찾지 못했을 때 디폴트값의 메세지로 응답하는 지 확인")
    void tokenNotFoundFromCookieException() throws Exception {
        mockMvc.perform(get("/test/token-not-found"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value("Token not found in cookies"))
                .andDo(print())
                .andReturn();
    }

    @Test
    @DisplayName("쿠키에서 토큰을 찾지 못했을 때 파라미터로 넣은 메세지로 응답하는 지 확인")
    void tokenNotFoundFromCookieException_byMessage() throws Exception {
        mockMvc.perform(get("/test/token-not-found/message"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value("message"))
                .andDo(print())
                .andReturn();
    }

    @Test
    @DisplayName("userName not Found Exception에 대하여 검증.")
    void userNameNotFoundException() throws Exception {
        mockMvc.perform(get("/test/auth-failed"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.error").value("Unauthorized"))
                .andExpect(jsonPath("$.message").value("아이디 또는 비밀번호가 올바르지 않습니다."))
                .andDo(print())
                .andReturn();
    }
}