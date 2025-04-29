package com.nhnacademy.auth.context;

import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

public class ApplicationContextHolder implements ApplicationContextAware {

    /**
     * 직접 Bean 주입을 안 하고 전역적으로 스프링 컨텍스트를 잡을 컨텍스트입니다.
     */
    @Getter
    @Setter
    private static ApplicationContext context;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        context = applicationContext;
    }

}
