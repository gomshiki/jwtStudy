package com.jwtProject.jwt;

import com.jwtProject.domain.User;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class JwtSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private  TokenProvider tokenProvider;

    // TokenProvider 생성자 주입
    public JwtSecurityConfig(TokenProvider tokenProvider) {

        this.tokenProvider = tokenProvider;
    }

    @Override
    public void configure(HttpSecurity http) {

        // JwtFilter를 이용해 작성한 tokenProvider를 customFilter 인스턴스를 만들고
        JwtFilter customFilter = new JwtFilter(tokenProvider);

        // HttpSecurity addFilterBefore 메서드를 이용해 이용해 Spring Security 필터에 customFilter 를 등록합니다.
        http.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
