package com.example.springsecuritystudy.domain;

import static com.example.springsecuritystudy.global.jwt.JwtUtil.getMemberId;
import static com.example.springsecuritystudy.global.jwt.JwtUtil.isValidAccess;

import java.util.List;

import javax.persistence.EntityNotFoundException;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.springsecuritystudy.global.config.SecurityConfig;
import com.example.springsecuritystudy.global.jwt.JwtTokenProvider;
import com.example.springsecuritystudy.global.jwt.TokenInfo;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class MemberService {

	// TODO Redis 도입!

	private final MemberRepository memberRepository;
	private final JwtTokenProvider jwtTokenProvider;

	private final List<String> userOnlyRoles = List.of("USER");
	private final List<String> adminOnlyRoles = List.of("ADMIN");
	private final List<String> userAndAdminRoles = List.of("ADMIN", "USER");

	@Transactional
	public Long registerMember(MemberDto dto){
		Member member = memberRepository.save(
				Member.builder()
						.email(dto.email())
						.password(dto.password())
						.roles(userOnlyRoles)
						.build()
		);

		return member.getId();
	}

	@Transactional(readOnly = true)
	public Long getCurMemberId() {
		return getMemberId();
	}


	@Transactional(readOnly = true)
	public TokenInfo login(String email, String enteredPassword) {
		Member member = memberRepository.findByEmail(email).orElseThrow(() -> new EntityNotFoundException(""));
		if (isPasswordMatches(member, enteredPassword)) {
			return generateToken(member.getId(), enteredPassword);
		}
		return null;
	}

	public void logout() {
		SecurityContextHolder.clearContext();
	}


	// TODO 현재는 RefreshToken 을 가지고 있으면
	// 해당 정보를 가지고 유저를 찾아서 AccessToken 을 재발급해줌
	// 근데 이게 비밀번호를 DB 에서 꺼내오는 작업을 수행하는게 뭔가 꺼림칙함....
	// 애초에 로직이 잘못된 건지...
	// UserDetail 을 사용하고 싶어서 사용은 하는데... 근본적으로 accessToken -> memberId 만으로도
	// authentication 을 통해서 AccessToken 을 발급하는 방법이 존재하는지 궁금!!

	@Transactional
	public TokenInfo reissue(ReissueRequest request){
		jwtTokenProvider.validateToken(request.refreshToken());
		String memberId = jwtTokenProvider.getMemberIdFromToken(request.accessToken());
		return jwtTokenProvider.generateToken(request.accessToken());
	}


	private boolean isPasswordMatches(Member member, String enteredPassword){
		return member.isPasswordMatches(enteredPassword);
	}

	private TokenInfo generateToken(Long memberId, String enteredPassword){
		return jwtTokenProvider.generateToken(String.valueOf(memberId), enteredPassword);
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
}
