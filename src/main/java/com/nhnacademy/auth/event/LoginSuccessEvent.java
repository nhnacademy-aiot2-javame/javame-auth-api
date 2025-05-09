package com.nhnacademy.auth.event;

import org.springframework.context.ApplicationEvent;

public class LoginSuccessEvent extends ApplicationEvent {

    /**
     * MemberAdaptor에게 넘겨줄 memberEmail.
     */
    private final String memberEmail;

    public LoginSuccessEvent(Object source, String memberEmail) {
        super(source);
        this.memberEmail = memberEmail;
    }

    public String getMemberEmail() {
        return memberEmail;
    }
}
