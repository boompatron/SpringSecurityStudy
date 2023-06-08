package com.example.springsecuritystudy.domain;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.springsecuritystudy.global.jwt.CookieProvider;
import com.example.springsecuritystudy.global.jwt.TokenInfo;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/members")
public class MemberController {

	private final MemberService memberService;
	private final CookieProvider cookieProvider;

	@PostMapping("/login")
	public ResponseEntity<TokenInfo> login(@RequestBody MemberLoginRequest request){
		String memberId = request.memberId();
		String password = request.password();
		TokenInfo tokenInfo = memberService.login(memberId, password);

		ResponseCookie responseCookie = cookieProvider.generateTokenCookie(tokenInfo.getRefreshToken());

		return ResponseEntity.ok()
				.header(HttpHeaders.SET_COOKIE, responseCookie.toString())
				.body(tokenInfo);
	}

	@PostMapping("/test")
	public String test(){
		return "success";
	}

	// @PostMapping("/reissue")
	// public ResponseEntity<TokenInfo> reissue(
	// 		@CookieValue String refreshToken,
	// 		String accessToken
	// ){
	//
	// }
}
