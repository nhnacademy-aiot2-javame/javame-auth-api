package com.nhnacademy.auth.adaptor;

import com.nhnacademy.auth.dto.LoginRequest;
import com.nhnacademy.auth.dto.LoginResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

//유레카 서버에 등록된 서비스 이름을 name에다 써주고 url을 서버 내부에서 통신할 수 있게 해줘야함.

/**
 * 서버끼리만 통신할 때 쓰는 Adaptor. id, pw, role 정보가 들어있습니다.
 */
@FeignClient(name = "MemberService", url = "http://localhost:10256/api/v1/login")
public interface LoginAdaptor {
    @GetMapping
    ResponseEntity<LoginResponse> getLogin(LoginRequest loginRequest);

    @GetMapping("{/member-id}")
    ResponseEntity<LoginResponse> getLoginInfo(@PathVariable("member-id") String memberId);
}
