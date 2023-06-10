package com.example.springsecuritystudy.global.exception.custom;

import com.example.springsecuritystudy.global.exception.ExceptionCode;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class InvalidRefreshTokenException extends RuntimeException{

	public InvalidRefreshTokenException(String memberId) {
		super(ExceptionCode.INVALID_REFRESH_TOKEN.getMessage());
		log.info("Invalid Refresh Token used. R.T Owner ID : {}", memberId);
	}
}
