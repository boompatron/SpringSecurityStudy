package com.example.springsecuritystudy.global.jwt;

import lombok.Builder;
import lombok.Getter;

@Getter
public class TokenInfo {

	private final String grantType;
	private final String accessToken;
	private final String refreshToken;

	@Builder
	public TokenInfo(String grantType, String accessToken, String refreshToken) {
		this.grantType = grantType;
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
	}
}
