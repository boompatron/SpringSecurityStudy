package com.example.springsecuritystudy.domain;

public record MemberLoginRequest(
		String memberId,
		String password
) {
}
