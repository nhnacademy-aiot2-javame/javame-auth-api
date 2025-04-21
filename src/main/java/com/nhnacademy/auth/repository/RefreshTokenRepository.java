package com.nhnacademy.auth.repository;

import com.nhnacademy.auth.dto.RefreshToken;
import org.springframework.data.repository.CrudRepository;

public interface RefreshTokenRepository extends CrudRepository<RefreshToken, String> {
}
