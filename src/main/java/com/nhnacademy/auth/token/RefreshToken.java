package com.nhnacademy.auth.token;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

@ToString
@EqualsAndHashCode
@RedisHash(value = "refreshToken", timeToLive = 604800)
public class RefreshToken {
    /**
     * Redis에 담길 RefreshToken의 Key값입니다.
     */
    @Id
    @JsonProperty
    private String id;

    /**
     *  Redis에 담길 RefreshToken의 value값 입니다.
     */
    @JsonProperty
    private String refreshToken;

    public RefreshToken() {
        // NoArgsConstructor
    }

    public RefreshToken(String id, String refreshToken) {
        this.id = id;
        this.refreshToken = refreshToken;
    }

    public String getId() {
        return id;
    }

    public String getRefreshToken() {
        return refreshToken;
    }
}
