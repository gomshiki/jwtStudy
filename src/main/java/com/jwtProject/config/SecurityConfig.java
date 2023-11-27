package com.jwtProject.config;

import static org.springframework.security.config.Customizer.withDefaults;

import com.jwtProject.jwt.JwtAccessDeniedHandler;
import com.jwtProject.jwt.JwtAuthenticationEntryPoint;
import com.jwtProject.jwt.JwtSecurityConfig;
import com.jwtProject.jwt.TokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint   jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler    jwtAccessDeniedHandler;

    public SecurityConfig(TokenProvider tokenProvider,
            JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            JwtAccessDeniedHandler jwtAccessDeniedHandler) {
        this.tokenProvider = tokenProvider;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }

    @Bean
    public PasswordEncoder  passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public WebSecurityCustomizer configure() {
        // h2-console 및 favicon 하위 요청은 모두 무시
        return (web) -> web.ignoring()
                .requestMatchers(new AntPathRequestMatcher("/h2-console/**"))
                .requestMatchers(new AntPathRequestMatcher("/favicon.ico"));
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {

        httpSecurity
                .csrf(AbstractHttpConfigurer::disable)

                .exceptionHandling((handling) ->
                        handling.authenticationEntryPoint(jwtAuthenticationEntryPoint)
                                .accessDeniedHandler(jwtAccessDeniedHandler)
                )

                .headers((header) -> header.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))

                .sessionManagement((session)->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))


                .authorizeHttpRequests((registry) ->
                        registry.requestMatchers(

                                new AntPathRequestMatcher("/api/hello"),
                                new AntPathRequestMatcher("/api/authenticate"),
                                new AntPathRequestMatcher("/api/signup")
                                        )
                                .permitAll()
                                .anyRequest().authenticated()
                )

                .apply(new JwtSecurityConfig(tokenProvider));


                return httpSecurity.build();
    }
}


