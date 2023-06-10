package com.example.springsecuritystudy.domain;

import static com.example.springsecuritystudy.global.jwt.JwtUtil.getMemberId;

import java.util.List;

import javax.persistence.EntityNotFoundException;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.springsecuritystudy.global.exception.custom.InvalidRefreshTokenException;
import com.example.springsecuritystudy.global.jwt.JwtTokenProvider;
import com.example.springsecuritystudy.global.jwt.TokenInfo;
import com.example.springsecuritystudy.global.redis.CacheRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class MemberService {

	// TODO Redis 도입!
	private static final List<String> userOnlyRoles = List.of("USER");
	private static final List<String> adminOnlyRoles = List.of("ADMIN");
	private static final List<String> userAndAdminRoles = List.of("ADMIN", "USER");

	private final MemberRepository memberRepository;
	private final JwtTokenProvider jwtTokenProvider;
	private final CacheRepository<String> cacheRepository;

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
			TokenInfo tokenInfo = generateToken(member.getId(), enteredPassword);
			cacheRepository.save(String.valueOf(member.getId()), tokenInfo.getRefreshToken());
			return tokenInfo;
		}
		return null;
	}

	public void logout() {
		cacheRepository.delete(String.valueOf(getMemberId()));
		SecurityContextHolder.clearContext();
	}


	// TODO 현재는 RefreshToken 을 가지고 있으면
	// 해당 정보를 가지고 유저를 찾아서 AccessToken 을 재발급해줌
	// 근데 이게 비밀번호를 DB 에서 꺼내오는 작업을 수행하는게 뭔가 꺼림칙함....
	// 애초에 로직이 잘못된 건지...
	// UserDetail 을 사용하고 싶어서 사용은 하는데... 근본적으로 accessToken -> memberId 만으로도
	// authentication 을 통해서 AccessToken 을 발급하는 방법이 존재하는지 궁금!!
	@Transactional
	public TokenInfo reissue(ReissueRequest request, String refreshToken){
		jwtTokenProvider.validateToken(refreshToken);
		// A.T vs R.T 둘 중에 뭐를 하는게 더 좋을지 고민
		String memberId = jwtTokenProvider.getMemberIdFromToken(request.accessToken());

		if (!refreshToken.equals(cacheRepository.get(memberId))){
			throw new InvalidRefreshTokenException(jwtTokenProvider.getMemberIdFromToken(refreshToken));
		}

		TokenInfo tokenInfo = jwtTokenProvider.generateToken(request.accessToken());
		cacheRepository.delete(memberId);
		cacheRepository.save(memberId, tokenInfo.getRefreshToken());
		return tokenInfo;
	}


	private boolean isPasswordMatches(Member member, String enteredPassword){
		return member.isPasswordMatches(enteredPassword);
	}

	private TokenInfo generateToken(Long memberId, String enteredPassword){
		return jwtTokenProvider.generateToken(String.valueOf(memberId), enteredPassword);
	}

}
