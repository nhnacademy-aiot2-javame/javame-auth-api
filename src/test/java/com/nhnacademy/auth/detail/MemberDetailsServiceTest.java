package com.nhnacademy.auth.detail;

import com.nhnacademy.auth.member.adaptor.MemberAdaptor;
import com.nhnacademy.auth.member.response.MemberLoginResponse;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class MemberDetailsServiceTest {

    @Mock
    private MemberAdaptor memberAdaptor;

    @InjectMocks
    private MemberDetailsService memberDetailsService;

    @Test
    @DisplayName("loadUserByUsername이 성공했을 때.")
    void loadUserByUsername_success() {
        // given
        MemberLoginResponse loginResponse = new MemberLoginResponse(1L, "test@test.com", "encodedPassword", "USER");
        ResponseEntity<MemberLoginResponse> response = ResponseEntity.ok(loginResponse);

        Mockito.when(memberAdaptor.getLoginInfoByEmail(loginResponse.getMemberEmail())).thenReturn(response);

        // when
        MemberDetails memberDetails = (MemberDetails) memberDetailsService.loadUserByUsername(loginResponse.getMemberEmail());

        // then
        Assertions.assertThat(memberDetails).isInstanceOf(MemberDetails.class);
        Assertions.assertThat(memberDetails.getUsername()).isEqualTo(loginResponse.getMemberEmail());
        Assertions.assertThat(memberDetails.getPassword()).isEqualTo(loginResponse.getMemberPassword());
    }

    @Test
    @DisplayName("loadUserByUsername에서 username이 null이면 예외발생 검증. ")
    void loadUserByUsername_usernameNull() {
        Assertions.assertThatThrownBy(() -> memberDetailsService.loadUserByUsername(null))
                .isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    @DisplayName("loadUserByUsername에서 응답이 null이면 예외발생 검증. ")
    void loadUserByUsername_failed() {
        // given
        String email = "nonexistent@example.com";
        Mockito.when(memberAdaptor.getLoginInfoByEmail(email)).thenReturn(ResponseEntity.ok(null));

        // expect
        Assertions.assertThatThrownBy(() -> memberDetailsService.loadUserByUsername(email))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessage("사용자를 찾을 수 없습니다.");
    }
}
