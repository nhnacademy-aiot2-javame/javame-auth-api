package com.nhnacademy.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

@RedisHash(value = "refreshToken", timeToLive = 7)
@AllArgsConstructor
@Getter
@ToString
public class RefreshToken {
    /**
     * Redis에 담길 RefreshToken의 Key값입니다.
     */
    @Id
    private String id;

    /**
     *  Redis에 담길 RefreshToken의 value값 입니다.
     */
    private String refreshToken;
}
