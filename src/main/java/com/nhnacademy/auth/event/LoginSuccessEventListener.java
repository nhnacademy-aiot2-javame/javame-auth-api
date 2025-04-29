package com.nhnacademy.auth.event;

import com.nhnacademy.auth.member.adaptor.MemberAdaptor;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

@Component
public class LoginSuccessEventListener {

    /**
     * Member Service와 연결하는 어댑터입니다.
     */
    private final MemberAdaptor memberAdaptor;

    public LoginSuccessEventListener(MemberAdaptor memberAdaptor) {
        this.memberAdaptor = memberAdaptor;
    }

    @Async
    @EventListener
    public void handleLoginSuccess(LoginSuccessEvent event) {
        String email = event.getMemberEmail();
        memberAdaptor.updateLastLogin(email);
    }
}
