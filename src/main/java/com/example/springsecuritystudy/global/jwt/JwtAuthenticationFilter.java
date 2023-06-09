package com.example.springsecuritystudy.global.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.filter.OncePerRequestFilter;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends GenericFilterBean {

	private final JwtTokenProvider jwtTokenProvider;

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws
			IOException,
			ServletException {

		// 1. Request Header 에서 JWT 토큰 추출
		String token = getTokenFromHeader((HttpServletRequest) request);

		// 2. validateToken 으로 토큰 유효성 검증
		if (token != null) {
			jwtTokenProvider.validateToken(token);
			Authentication authentication = jwtTokenProvider.getAuthentication(token);
			SecurityContextHolder.getContext().setAuthentication(authentication);
		}

		chain.doFilter(request, response);
	}
	// @Override
	// protected void doFilterInternal(
	// 		HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
	// 		throws ServletException, IOException {
	//
	// 	// 1. Request Header 에서 JWT 토큰 추출
	// 	String token = getTokenFromHeader((HttpServletRequest)request);
	//
	// 	// 2. validateToken 으로 토큰 유효성 검증
	// 	if (token != null) {
	// 		jwtTokenProvider.validateToken(token);
	// 		Authentication authentication = jwtTokenProvider.getAuthentication(token);
	// 		SecurityContextHolder.getContext().setAuthentication(authentication);
	// 	}
	//
	// 	filterChain.doFilter(request, response);
	// }
	//
	// @Override
	// protected boolean shouldNotFilter(HttpServletRequest request) {
	// 	return request.getRequestURI().endsWith("reissue")
	// 			&& request.getMethod().equalsIgnoreCase("POST");
	// }

	private String getTokenFromHeader(HttpServletRequest request) {
		String bearerToken = request.getHeader("Authorization");
		if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer")) {
			return bearerToken.substring(7);
		}
		return null;
	}
}
