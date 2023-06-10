package com.example.springsecuritystudy.global.exception;

import static com.example.springsecuritystudy.global.exception.ExceptionResponse.toResponseEntity;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.example.springsecuritystudy.global.exception.custom.InvalidRefreshTokenException;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

	@ExceptionHandler({
			InvalidRefreshTokenException.class
	})
	public ResponseEntity<ExceptionResponse> handleInvalidRefreshTokenException(RuntimeException runtimeException){
		return toResponseEntity(ExceptionCode.INVALID_REFRESH_TOKEN);
	}
}
