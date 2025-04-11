package com.nhnacademy.auth.provider;

import com.nhnacademy.auth.dto.JwtTokenDto;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Date;
import static org.assertj.core.api.Assertions.assertThat;


@SpringBootTest(classes = JwtTokenProvider.class)
class JwtTokenProviderTest {
    static final Logger log = LoggerFactory.getLogger(JwtTokenProviderTest.class);

    @Autowired
    JwtTokenProvider jwtTokenProvider;

    private final String testEmail = "test@nhn.com";

    @Test
    @DisplayName("token 생성 후 validate 테스트")
    void generateTokenAndValidateTest() {
        // when
        JwtTokenDto token = jwtTokenProvider.generateTokenDto(testEmail);
        log.info("token : {}", token);

        // then
        assertThat(token).isNotNull();
        assertThat(jwtTokenProvider.validateToken(token.getAccessToken())).isTrue();
        assertThat(jwtTokenProvider.getUserEmailFromToken(token.getAccessToken())).isEqualTo(testEmail);
    }

    @Test
    @DisplayName("토큰 생성 후 DTO 검증.")
    void generateTokenDtoTest() {
        // when
        JwtTokenDto tokenDto = jwtTokenProvider.generateTokenDto(testEmail);
        log.info("tokenDto: {}", tokenDto);
        // then
        assertThat(tokenDto).isNotNull();
        assertThat(tokenDto.getAccessToken()).isNotNull();
        assertThat(tokenDto.getRefreshToken()).isNotNull();
        assertThat(tokenDto.getGrantType()).isEqualTo("Bearer");

        // access token 검증
        assertThat(jwtTokenProvider.validateToken(tokenDto.getAccessToken())).isTrue();
        assertThat(jwtTokenProvider.getUserEmailFromToken(tokenDto.getAccessToken())).isEqualTo(testEmail);
    }

    @Test
    @DisplayName("token 만료 후 검증")
    void expiredTokenShouldReturnFalse() throws InterruptedException {
        // given - 짧은 생명주기 토큰을 생성하고 sleep으로 만료시킴
        String expiredToken = Jwts.builder()
                .subject(testEmail)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 100)) // 100ms 후 만료
                .signWith(jwtTokenProvider.getKey()) // private key 접근을 위해 getter 필요
                .compact();

        Thread.sleep(200); // 토큰 만료 대기

        // then
        assertThat(jwtTokenProvider.validateToken(expiredToken)).isFalse();
    }
}