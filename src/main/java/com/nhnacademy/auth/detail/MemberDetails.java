package com.nhnacademy.auth.detail;

import com.nhnacademy.auth.member.response.MemberLoginResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

@Slf4j
public class MemberDetails implements UserDetails {

    /**
     *  서버 내부끼리 통신하는 LoginAdaptor를 통해 받은 id, pw, role 이 있는 dto 입니다.
     */
    private final MemberLoginResponse loginResponse;

    public MemberDetails(MemberLoginResponse loginResponse) {
        this.loginResponse = loginResponse;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority(loginResponse.getRoleId()));
    }

    @Override
    public String getPassword() {
        // DB에 이미 인코딩 된 password 값이므로 그대로 return 해 줌.
        return loginResponse.getMemberPassword();
    }

    @Override
    public String getUsername() {
        return loginResponse.getMemberEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return UserDetails.super.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return UserDetails.super.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return UserDetails.super.isCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return UserDetails.super.isEnabled();
    }
}
