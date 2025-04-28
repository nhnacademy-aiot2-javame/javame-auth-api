package com.nhnacademy.auth.detail;

import com.nhnacademy.auth.member.adaptor.MemberAdaptor;
import com.nhnacademy.auth.member.response.MemberLoginResponse;
import org.apache.commons.lang.StringUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class MemberDetailsService implements UserDetailsService {
    /**
     * 회원 정보를 가져오는 adaptor.
     */
    private final MemberAdaptor memberAdaptor;

    public MemberDetailsService(MemberAdaptor memberAdaptor) {
        this.memberAdaptor = memberAdaptor;
    }

    /**
     *
     * @param username the username identifying the user whose data is required.
     * @return DB에서 찾은 사용자를 MemberDetails에 넘겨 타입을 MemberDetails로 변환시킵니다.
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (StringUtils.isEmpty(username)) {
            throw new UsernameNotFoundException(String.format("%s not found.", username));
        }

        MemberLoginResponse loginResponse = memberAdaptor.getLoginInfoByEmail(username).getBody();
        if (loginResponse == null) {
            throw new UsernameNotFoundException("사용자를 찾을 수 없습니다.");
        }
        return new MemberDetails(loginResponse);
    }
}
