package com.example.springsecuritystudy.domain;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
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

	@PostMapping("/signUp")
	public ResponseEntity<Long> signUp(
			@RequestBody MemberDto dto
	) {
		return ResponseEntity.ok(memberService.registerMember(dto));
	}

	@PostMapping("/login")
	public ResponseEntity<TokenInfo> login(@RequestBody MemberDto request){
		String email = request.email();
		String password = request.password();
		TokenInfo tokenInfo = memberService.login(email, password);

		ResponseCookie responseCookie = cookieProvider.getRefreshTokenResponseCookie(tokenInfo.getRefreshToken());

		return ResponseEntity.ok()
				.header(HttpHeaders.SET_COOKIE, responseCookie.toString())
				.body(tokenInfo);
	}

	@PostMapping("/test")
	public String test(){
		return "success";
	}

	@GetMapping("/id")
	public ResponseEntity<Long> getMemberId(){
		return ResponseEntity.ok(memberService.getCurMemberId());
	}

	@DeleteMapping("/logout")
	public ResponseEntity<Void> logout(){
		memberService.logout();
		ResponseCookie responseCookie = cookieProvider.generateResetResponseCookie();
		return ResponseEntity.ok()
				.header(HttpHeaders.SET_COOKIE, responseCookie.toString())
				.build();
	}

	@PostMapping("/reissue")
	public ResponseEntity<TokenInfo> reissue(
			@CookieValue String refreshToken,
			@RequestBody ReissueRequest request
	){
		log.info("AT: {}", request.accessToken());
		log.info("RT: {}", refreshToken);
		TokenInfo tokenInfo = memberService.reissue(request, refreshToken);
		ResponseCookie responseCookie = cookieProvider.getRefreshTokenResponseCookie(tokenInfo.getRefreshToken());

		return ResponseEntity.ok()
				.header(HttpHeaders.SET_COOKIE, responseCookie.toString())
				.body(tokenInfo);
	}

	@GetMapping("/redis-get-test/{id}")
	public ResponseEntity<TestDto> getRedisCache(
			@PathVariable Long id
	){
		TestDto dto = memberService.redisCacheTest(id);
		return ResponseEntity.ok(dto);
	}
}
