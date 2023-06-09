package com.example.springsecuritystudy.global.jwt;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum JWT_KEYWORD {
	AUTHORIZATION("Authorization"),
	BEARER("Bearer"),
	REFRESH_TOKEN("refreshToken")
	;

	private final String word;
}
