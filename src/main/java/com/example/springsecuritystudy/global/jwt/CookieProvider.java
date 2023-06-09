package com.example.springsecuritystudy.global.jwt;

import org.springframework.boot.web.server.Cookie;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class CookieProvider {

	private static final String REFRESH_TOKEN = "refreshToken";
	private static final int RESET_AGE = 0;
	private static final int REFRESH_TOKEN_EXPIRE_AGE = 604800000;

	public ResponseCookie getRefreshTokenResponseCookie(String refreshToken){
		return generateResponseCookie(refreshToken)
				.maxAge(REFRESH_TOKEN_EXPIRE_AGE)
				.build();
	}

	public ResponseCookie generateResetResponseCookie() {
		return generateResponseCookie("")
				.maxAge(RESET_AGE)
				.build();
	}

	// TODO SSL 인증서 및 Nginx 도입 후 .secure(true) 옵션 활성화하기
	private ResponseCookie.ResponseCookieBuilder generateResponseCookie(String refreshToken){
		return ResponseCookie.from(REFRESH_TOKEN, refreshToken)
				.httpOnly(true)
				.path("/")
				.sameSite(Cookie.SameSite.NONE.attributeValue());
	}
}
