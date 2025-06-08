package com.nhnacademy.auth.repository;

import com.nhnacademy.auth.config.RedisConfig;
import com.nhnacademy.auth.token.JwtTokenDto;
import com.nhnacademy.auth.token.RefreshToken;
import com.nhnacademy.auth.provider.JwtTokenProvider;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.data.redis.DataRedisTest;
import org.springframework.context.annotation.Import;

import java.util.Optional;

@DataRedisTest
@Import(RedisConfig.class)
class RefreshTokenRepositoryTest {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenRepositoryTest.class);

    @Value("${token.prefix}")
    private String tokenPrefix;

    @Value("${jwt.secret}")
    private String key;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;


    @Test
    @DisplayName("Refresh token Redis 저장 및 조회")
    void saveAndFindeRefreshToken(){
        JwtTokenProvider jwtTokenProvider = new JwtTokenProvider(key);
        JwtTokenDto jwtTokenDto = jwtTokenProvider.generateTokenDto("test@test.com", "ROLE_USER");
        String redisKey = DigestUtils.sha256Hex(tokenPrefix + ":" + "test@test.com");
        log.info("redisKey: {}", redisKey);
        RefreshToken refreshToken = new RefreshToken(redisKey, jwtTokenDto.getRefreshToken(), "testUserAgent", "testIp");

        refreshTokenRepository.save(refreshToken);
        Optional<RefreshToken> result = refreshTokenRepository.findById(redisKey);

        log.info("result: {}", result);
        Assertions.assertNotNull(result);
        Assertions.assertEquals(jwtTokenDto.getRefreshToken(), result.get().getToken());
    }
}
