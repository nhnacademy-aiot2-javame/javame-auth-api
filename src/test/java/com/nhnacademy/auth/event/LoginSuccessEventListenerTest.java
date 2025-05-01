package com.nhnacademy.auth.event;

import com.nhnacademy.auth.config.SecurityConfig;
import com.nhnacademy.auth.member.adaptor.MemberAdaptor;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@SpringBootTest
@Import(SecurityConfig.class)
class LoginSuccessEventListenerTest {

    @MockitoBean
    private MemberAdaptor memberAdaptor;

    @Autowired
    private ApplicationEventPublisher eventPublisher;

    @Test
    @DisplayName("이벤트 발생시 updatelastLogin 호출 하는지 검증. ")
    void loginSuccessEvent_updateLastLogin() {
        // given
        String email = "test@example.com";
        LoginSuccessEvent event = new LoginSuccessEvent(new Object(), email);

        // when
        eventPublisher.publishEvent(event);

        Mockito.verify(memberAdaptor, Mockito.times(1)).updateLastLogin(email);
    }
}