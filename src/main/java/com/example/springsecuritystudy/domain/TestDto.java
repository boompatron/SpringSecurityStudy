package com.example.springsecuritystudy.domain;

import com.example.springsecuritystudy.global.jwt.TokenInfo;

public record TestDto(
		TokenInfo tokenInfo,
		String refreshToken
) {
}
