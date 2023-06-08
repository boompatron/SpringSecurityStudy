package com.example.springsecuritystudy.global.jwt;

import java.util.Objects;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JwtUtil {

	public static long getMemberId(){
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		log.info("authentication : {}", authentication);
		log.info("authen name : {}", authentication.getName());
		return Long.parseLong(authentication.getName());
	}

	public static boolean isValidAccess(long memberId) {
		return Objects.equals(JwtUtil.getMemberId(), memberId);
	}
}
