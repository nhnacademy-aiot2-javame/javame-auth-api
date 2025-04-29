package com.nhnacademy.auth.provider;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nhnacademy.auth.exception.TokenNotFoundFromCookie;
import com.nhnacademy.auth.token.JwtTokenDto;
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

@SpringBootTest(classes = JwtTokenProvider.class)
@ExtendWith(MockitoExtension.class)
class JwtTokenProviderTest {

    static final Logger log = LoggerFactory.getLogger(JwtTokenProviderTest.class);

    @Value("${jwt.secret}")
    private String key;

    private final String testEmail = "test@test.com";

    private final String testRole = "ROLE_USER";

    private JwtTokenProvider provider;

    ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp(){
        provider = new JwtTokenProvider(key);
    }

    @Test
    @DisplayName("token 생성 테스트")
    void generateTokenDto() {
        JwtTokenDto jwtTokenDto = provider.generateTokenDto(testEmail, testRole);

        log.info("jwtTokenDto: {}", jwtTokenDto);
        Assertions.assertNotNull(jwtTokenDto);
        Assertions.assertEquals(testEmail, provider.getUserEmailFromToken(jwtTokenDto.getAccessToken()));
    }

    @Test
    @DisplayName("cookie에서 resolveToken 가져오기")
    void resolveTokenFromCookie() {
        JwtTokenDto jwtTokenDto = provider.generateTokenDto(testEmail, testRole);

        Cookie cookie1 = new Cookie("accessToken", jwtTokenDto.getAccessToken());
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);

        Mockito.when(request.getCookies()).thenReturn(new Cookie[]{cookie1});

        String actual = provider.resolveTokenFromCookie(request);

        Assertions.assertNotNull(actual);
        Assertions.assertEquals(jwtTokenDto.getAccessToken(), actual);
    }

    @Test
    @DisplayName("cookie가 비어있을 땐 null이 나오는지")
    void resolveTokenFromCookie_isNull() {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getCookies()).thenReturn(new Cookie[]{});
        String actual = provider.resolveTokenFromCookie(request);

        Assertions.assertNull(actual);
    }

    @Test
    @DisplayName("cookie에서 토큰이 없을 때 TokenNotFoundFromCookie Exception 검증.")
    void resolveTokenFromCookie_notFound() {
        Cookie cookie1 = new Cookie("type", "Bearer");
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);

        Mockito.when(request.getCookies()).thenReturn(new Cookie[]{cookie1});

        Assertions.assertThrows(TokenNotFoundFromCookie.class, ()->{
            provider.resolveTokenFromCookie(request);
        });
    }


    @Test
    @DisplayName("accesstoken에서 subject에 저장한 userEmail 가져오기 ")
    void getUserEmailFromToken() {
        JwtTokenDto jwtTokenDto = provider.generateTokenDto(testEmail, testRole);
        String actual = provider.getUserEmailFromToken(jwtTokenDto.getAccessToken());
        Assertions.assertNotNull(actual);
        Assertions.assertEquals(testEmail, actual);
    }


    @Test
    @DisplayName("accesToken에서 role id 가져오기")
    void getRoleIdFromTokenTest() {
        JwtTokenDto jwtTokenDto = provider.generateTokenDto(testEmail, testRole);
        String accessTokenRole = provider.getRoleIdFromToken(jwtTokenDto.getAccessToken());
        String refreshTokenRole = provider.getRoleIdFromToken(jwtTokenDto.getRefreshToken());

        Assertions.assertNotNull(accessTokenRole);
        Assertions.assertNotNull(refreshTokenRole);

        Assertions.assertEquals(testRole, accessTokenRole);
        Assertions.assertEquals(testRole, refreshTokenRole);
    }

}