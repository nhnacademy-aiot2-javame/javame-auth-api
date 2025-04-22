package com.nhnacademy.auth.provider;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nhnacademy.auth.dto.JwtTokenDto;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(classes = JwtTokenProvider.class)
@ExtendWith(MockitoExtension.class)
class JwtTokenProviderTest {

    static final Logger log = LoggerFactory.getLogger(JwtTokenProviderTest.class);

    @Value("${jwt.secret}")
    private String key;

    private final String testEmail = "test@test.com";

    private JwtTokenProvider provider;

    ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp(){
        provider = new JwtTokenProvider(key);
    }

    @Test
    @DisplayName("token 생성 테스트")
    void generateTokenDto() {
        JwtTokenDto jwtTokenDto = provider.generateTokenDto(testEmail);

        log.info("jwtTokenDto: {}", jwtTokenDto);
        Assertions.assertNotNull(jwtTokenDto);
        Assertions.assertEquals(testEmail, provider.getUserEmailFromToken(jwtTokenDto.getAccessToken()));
    }

    @Test
    @DisplayName("cookie에서 resolveToken 가져오기")
    void resolveTokenFromCookie() throws JsonProcessingException {
        JwtTokenDto jwtTokenDto = provider.generateTokenDto(testEmail);

        Cookie cookie1 = new Cookie("accessToken", jwtTokenDto.getAccessToken());
        Cookie cookie2 = new Cookie("refreshToken", jwtTokenDto.getRefreshToken());

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);

        Mockito.when(request.getCookies()).thenReturn(new Cookie[]{cookie1, cookie2});

        JwtTokenDto actual = provider.resolveTokenFromCookie(request);

        Assertions.assertNotNull(actual);
        Assertions.assertEquals(jwtTokenDto.getAccessToken(), actual.getAccessToken());
        Assertions.assertEquals(jwtTokenDto.getRefreshToken(), actual.getRefreshToken());
    }

    @Test
    @DisplayName("cookie에서 resolveToken이 없을 경우 null이 나오는지")
    void resolveTokenFromCookie_notFound() {
        JwtTokenDto jwtTokenDto = provider.generateTokenDto(testEmail);

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);

        Mockito.when(request.getCookies()).thenReturn(new Cookie[]{});

        JwtTokenDto actual = provider.resolveTokenFromCookie(request);

        Assertions.assertNull(actual);
    }



    @Test
    @DisplayName("accesstoken에서 subject에 저장한 userEmail 가져오기 ")
    void getUserEmailFromToken() {
        JwtTokenDto jwtTokenDto = provider.generateTokenDto(testEmail);
        String actual = provider.getUserEmailFromToken(jwtTokenDto.getAccessToken());
        Assertions.assertNotNull(actual);
        Assertions.assertEquals(testEmail, actual);
    }

}