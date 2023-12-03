package com.jwtProject.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;


/**
 *
 */
public class JwtFilter extends GenericFilterBean {

    private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);

    public static final String AUTHORIZATION_HEADER = "Authorization";

    private TokenProvider tokenProvider;

    public JwtFilter(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }


    /**
     *  1) 필터링 로직 정의
     *  2) 토큰의 인증정보를 SecurityContext에 저장하는 메서드
     */
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {

        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;

        // Reques에서 토큰을 받아옴
        String jwt = resolveToken(httpServletRequest);

        String requestURI = httpServletRequest.getRequestURI();

        // 받아온 jwt 토큰을 validateToken 메서드로 유효성 검증
        if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {

            // 토큰이 정상이라면 Authentication 객체를 받아옴
            Authentication authentication = tokenProvider.getAuthentication(jwt);

            // SecurityContext에 Authentication 객체를 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);
            logger.debug("Security Context에 '{}' 인증정보를 저장했습니다., uri: {}", authentication.getName(),
                    requestURI);
        } else {
            logger.debug("유효한 JWT 토큰이 없습니다, uri : {}", requestURI);
        }

        filterChain.doFilter(servletRequest, servletResponse);

    }

    // Request Header 에서 토큰 정보를 꺼내오기 위한 resolveToken 메서드 정의
    private String resolveToken(HttpServletRequest request) {

        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
