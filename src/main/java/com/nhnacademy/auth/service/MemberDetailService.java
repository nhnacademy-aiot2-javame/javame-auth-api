package com.nhnacademy.auth.service;

import com.nhnacademy.auth.adaptor.MemberAdaptor; // <<<--- 수정된 어댑터 사용 확인
import com.nhnacademy.auth.dto.LoginResponse;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service; // <<<--- @Service 어노테이션 추가 필요
import feign.FeignException; // <<<--- Feign 예외 처리 위해 추가
import lombok.RequiredArgsConstructor; // <<<--- 생성자 주입 간소화 위해 추가
import lombok.extern.slf4j.Slf4j; // <<<--- 로깅 위해 추가

@Slf4j // <<<--- 로거 사용
@Service // <<<--- 스프링 빈으로 등록하기 위해 추가
@RequiredArgsConstructor // <<<--- final 필드 생성자 자동 생성 (Lombok)
public class MemberDetailService implements UserDetailsService {

    // @RequiredArgsConstructor가 생성자 자동 생성
    private final MemberAdaptor memberAdaptor;

    // @RequiredArgsConstructor 사용 시 생성자 직접 작성 불필요
    // public MemberDetailService(MemberAdaptor memberAdaptor) {
    //     this.memberAdaptor = memberAdaptor;
    // }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.debug("사용자 정보 로드 시도: {}", username); // <<<--- 디버그 로그 추가

        LoginResponse loginResponse = null; // <<<--- 변수 선언 위치 변경
        try {
            // MemberAdaptor를 통해 Member API 호출 (이전 단계에서 Adaptor 경로/반환타입 수정 완료 가정)
            loginResponse = memberAdaptor.getLoginInfoByMemberId(username); // <<<--- 직접 DTO 반환 방식 사용
            log.debug("Member API 응답 수신: {}", username);

            // loginResponse 자체는 null이 아닐 수 있으나, 내부 필드가 null일 수 있음 (API 설계에 따라)
            // 여기서는 loginResponse가 null이면 사용자 못 찾음으로 간주 (FeignException 처리에서 더 명확해짐)

        } catch (FeignException.NotFound e) { // <<<--- (개선) Member API가 404 반환 시 처리
            log.warn("Member API에서 사용자를 찾지 못함: {}", username, e);
            throw new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + username, e);
        } catch (FeignException e) { // <<<--- (개선) 그 외 Feign 호출 오류 (네트워크, Member API 서버 오류 등)
            log.error("Member API 호출 중 오류 발생: status={}, username={}", e.status(), username, e);
            // 더 구체적인 예외 타입으로 변환하거나, 적절한 메시지와 함께 UsernameNotFoundException 던지기 가능
            // 여기서는 일반적인 메시지로 처리
            throw new UsernameNotFoundException("사용자 정보 조회 중 오류 발생: " + username, e);
        } catch (Exception e) { // <<<--- 그 외 예상치 못한 예외
            log.error("사용자 정보 로드 중 알 수 없는 오류 발생: username={}", username, e);
            throw new UsernameNotFoundException("사용자 정보 로드 중 알 수 없는 오류 발생: " + username, e);
        }

        // loginResponse가 null일 수 있는 케이스는 FeignException.NotFound에서 처리됨
        // 하지만 방어적으로 한번 더 체크
        if (loginResponse == null || loginResponse.getMemberId() == null) { // <<<--- loginResponse 또는 주요 필드 null 체크
            log.error("Member API로부터 유효하지 않은 응답 수신: username={}", username);
            throw new UsernameNotFoundException("사용자 정보를 찾을 수 없습니다(Invalid Response): " + username);
        }

        // 조회된 LoginResponse 객체를 사용하여 MemberDetails 객체 생성 및 반환
        // MemberDetails 생성자에서 Null 체크 로직이 있다면 여기서 추가 Null 체크는 불필요할 수 있음
        return new MemberDetails(loginResponse);
    }
}
