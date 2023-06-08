package com.example.springsecuritystudy.domain;

import static com.example.springsecuritystudy.global.jwt.JwtUtil.getMemberId;

import java.util.List;

import javax.persistence.EntityNotFoundException;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.springsecuritystudy.global.jwt.JwtTokenProvider;
import com.example.springsecuritystudy.global.jwt.TokenInfo;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class MemberService {

	private final MemberRepository memberRepository;
	private final AuthenticationManagerBuilder authenticationManagerBuilder;
	private final JwtTokenProvider jwtTokenProvider;

	private List<String> roles = List.of("USER");

	@Transactional
	public Long registerMember(MemberDto dto){
		Member member = memberRepository.save(
				Member.builder()
						.email(dto.email())
						.password(dto.password())
						.roles(roles)
						.build()
		);

		return member.getId();
	}

	@Transactional(readOnly = true)
	public Long getCurMemberId() {
		return getMemberId();
	}

	// @Transactional(readOnly = true)
	// public TokenInfo login(String email, String password) {
	// 	// 1. Login ID/PW 를 기반으로 Authentication 객체 생성
	// 	// 이때 authentication 는 인증 여부를 확인하는 authenticated 값이 false
	// 	UsernamePasswordAuthenticationToken authenticationToken =
	// 			new UsernamePasswordAuthenticationToken(email, new Password(password).getPassword());
	//
	// 	// 2. 실제 검증 (사용자 비밀번호 체크)이 이루어지는 부분
	// 	// authenticate 매서드가 실행될 때 CustomUserDetailsService 에서 만든 loadUserByUsername 메서드가 실행
	// 	Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
	//
	// 	// 3. 인증 정보를 기반으로 JWT
	// 	TokenInfo tokenInfo = jwtTokenProvider.generateToken(authentication);
	//
	// 	return tokenInfo;
	// }

	@Transactional(readOnly = true)
	public TokenInfo login(String email, String enteredPassword) {
		Member member = memberRepository.findByEmail(email).orElseThrow(() -> new EntityNotFoundException(""));
		if (isPasswordMatches(member, enteredPassword)) {
			return generateToken(member.getId(), enteredPassword);
		}

		return null;
	}

	private boolean isPasswordMatches(Member member, String enteredPassword){
		return member.isPasswordMatches(enteredPassword);
	}

	private TokenInfo generateToken(Long memberId, String enteredPassword){
		return jwtTokenProvider.generateToken(memberId, enteredPassword);
	}


}
