package com.example.springsecuritystudy.global.jwt;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
public class TokenInfo {

	private final String grantType;
	private final String accessToken;
	private final String refreshToken;

	public TokenInfo(){
		this.grantType = "";
		this.accessToken = "";
		this.refreshToken = "";
	}

	@Builder
	public TokenInfo(String grantType, String accessToken, String refreshToken) {
		this.grantType = grantType;
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
	}
}
