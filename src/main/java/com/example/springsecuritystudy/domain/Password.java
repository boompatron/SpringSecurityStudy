package com.example.springsecuritystudy.domain;

import java.util.regex.Pattern;

import javax.persistence.Column;
import javax.persistence.Embeddable;
import javax.persistence.Transient;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Getter
@Embeddable
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Password {
	// 비밀번호는 8 ~ 15글자로 해주세요
	// 알파벳 소문자, 대문자, 숫자, !@#$%^&*()-=_+ 안의 특수문자
	// 4가지 종류가 필요합니다
	private static final String PASSWORD_PATTERN = "^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*()-=_+]).{8,15}$";

	@Transient
	private static final PasswordEncoder encoder = new BCryptPasswordEncoder();

	@Column(name = "password", nullable = false, unique = false, length = 80)
	private String password;

	public Password(String password){
		isValidPassword(password);
		this.password = encoder.encode(password);
	}

	public boolean isPasswordMatches(String enteredPassword){
		return encoder.matches(enteredPassword, this.password);
	}

	private void isValidPassword(String password){
		if (!Pattern.matches(PASSWORD_PATTERN, password))
			throw new IllegalArgumentException("비밀번호 형식을 맞춰주세요");
	}
}
