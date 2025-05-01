package com.nhnacademy.auth.provider;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nhnacademy.auth.exception.GenerateTokenDtoException;
import com.nhnacademy.auth.exception.MissingTokenException;
import com.nhnacademy.auth.exception.TokenNotFoundFromCookie;
import com.nhnacademy.auth.token.JwtTokenDto;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
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
import java.security.Key;
import java.util.Date;

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
    @DisplayName("토큰 dto 생성 시 userEmail이 empty일 때 - GenerateTokenDtoException 발생 검증.")
    void generateTokenDto_failedByUserEmail() {
        Assertions.assertThrows(GenerateTokenDtoException.class, () ->{
            provider.generateTokenDto("", testRole);
        });
    }

    @Test
    @DisplayName("토큰 dto 생성 시 userRole이 empty일 때 - GenerateTokenDtoException 발생 검증.")
    void generateTokenDto_failedByUserRole() {
        Assertions.assertThrows(GenerateTokenDtoException.class, () ->{
            provider.generateTokenDto(testEmail, "");
        });
    }

    @Test
    @DisplayName("jwt 검증 테스트")
    void validate_success() {
        JwtTokenDto jwtTokenDto = provider.generateTokenDto(testEmail, testRole);
        String accessToken = jwtTokenDto.getAccessToken();
        String refreshToken = jwtTokenDto.getRefreshToken();

        boolean actual = provider.validateToken(accessToken);
        boolean real = provider.validateToken(refreshToken);

        Assertions.assertTrue(actual);
        Assertions.assertTrue(real);
    }

    @Test
    @DisplayName("jwt 검증 실패 - 서명이 틀린 토큰")
    void validate_failed1() {
        String wrongSecretKey = key.replace("x", "p");
        byte[] keyBytes = Decoders.BASE64.decode(wrongSecretKey);
        Key worngKey = Keys.hmacShaKeyFor(keyBytes);

        String token = Jwts.builder()
                .subject(testEmail)
                .claim("role", testRole)
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime() + (60 * 30)))
                .signWith(worngKey)
                .compact();

        Assertions.assertFalse(provider.validateToken(token));
    }

    @Test
    @DisplayName("jwt 검증 실패 - 만료된 토큰")
    void validate_failed2() {
        byte[] keyBytes = Decoders.BASE64.decode(key);
        Key testKey = Keys.hmacShaKeyFor(keyBytes);
        String token = Jwts.builder()
                .subject("user1")
                .expiration(new java.util.Date(System.currentTimeMillis() - 1000))
                .signWith(testKey)
                .compact();

        boolean result = provider.validateToken(token);
        Assertions.assertFalse(result);
    }

    @Test
    @DisplayName("jwt 검증 실패 - 형식이 틀린 토큰")
    void validate_failed3() {
        String token = "not.a.valid.jwt";

        boolean result = provider.validateToken(token);
        Assertions.assertFalse(result);
    }

    @Test
    @DisplayName("jwt 검증 실패 - 지원되지 않는 형식의 JWT")
    void validate_failed4() {
        String token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyMSJ9."; // header: {"alg":"none"}, payload: {"sub":"user1"}

        boolean result = provider.validateToken(token);
        Assertions.assertFalse(result);
    }

    @Test
    @DisplayName("jwt 검증 실패 - 잘못된 인자 (IllegalArgumentException)")
    void validate_failed_illegalArgument() {
        boolean result1 = provider.validateToken(null);
        boolean result2 = provider.validateToken("   "); // 공백 문자열

        Assertions.assertFalse(result1);
        Assertions.assertFalse(result2);
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
    @DisplayName("parseclaimse에서 ExpiredJwtException 잡는 지 검증. ")
    void getUserEmailFromToken_ExpiredJwtException() {
        byte[] keyBytes = Decoders.BASE64.decode(key);
        Key testKey = Keys.hmacShaKeyFor(keyBytes);
        String token = Jwts.builder()
                .subject("user1")
                .expiration(new java.util.Date(System.currentTimeMillis() - 1000))
                .signWith(testKey)
                .compact();

        String subject = provider.getUserEmailFromToken(token);
        Assertions.assertEquals("user1", subject);
    }

    @Test
    @DisplayName("토큰이 null일 때 MissingTokenException 발생하는지 검증. ")
    void getUserEmailFromToken_failed() {
        Assertions.assertThrows(MissingTokenException.class, () -> {
            provider.getUserEmailFromToken("");
        });
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

    @Test
    @DisplayName("토큰이 비었을 때 MissingTokenException 발생 검증. ")
    void getRoleIdFromTokenTest_Failed() {
       Assertions.assertThrows(MissingTokenException.class, () -> {
           provider.getRoleIdFromToken("");
       });
    }
}
