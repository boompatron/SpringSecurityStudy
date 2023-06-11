package com.example.springsecuritystudy.domain;

import static com.example.springsecuritystudy.global.jwt.JwtUtil.getMemberId;

import java.util.List;

import javax.persistence.EntityNotFoundException;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.springsecuritystudy.global.exception.custom.InvalidRefreshTokenException;
import com.example.springsecuritystudy.global.jwt.JwtTokenProvider;
import com.example.springsecuritystudy.global.jwt.TokenInfo;
import com.example.springsecuritystudy.global.redis.CacheRepository;
import com.example.springsecuritystudy.global.redis.RedisTokenTemplate;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class MemberService {
	private static final List<String> userOnlyRoles = List.of("USER");
	private static final List<String> adminOnlyRoles = List.of("ADMIN");
	private static final List<String> userAndAdminRoles = List.of("ADMIN", "USER");


	private final MemberRepository memberRepository;
	private final JwtTokenProvider jwtTokenProvider;
	private final CacheRepository<String> cacheRepository;
	private final CacheRepository<TokenInfo> redisTokenTemplate;

	@Transactional
	public Long registerMember(MemberDto dto){
		// 일단은 일반 회원의 가입만 받음
		// 추가로 어드민 계정을 가진 회원을 가입시키는 추가 메소드 및 도에인 추가 예정
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
			cacheRepository.save(toCacheKey(String.valueOf(member.getId())), tokenInfo.getRefreshToken());
			redisTokenTemplate.save("Token" + member.getId().toString(), tokenInfo);
			 // tokenInfoCacheRepository.save(toCacheKey(member.getId().toString() + "Token"), tokenInfo);
			return tokenInfo;
		}
		return null;
	}

	public void logout() {
		cacheRepository.delete(toCacheKey(String.valueOf(getMemberId())));
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
		cacheRepository.delete(toCacheKey(memberId));
		cacheRepository.save(toCacheKey(memberId), tokenInfo.getRefreshToken());
		return tokenInfo;
	}

	@Transactional(readOnly = true)
	public TestDto redisCacheTest(Long id) {
		System.out.println("Token" + id.toString() + "," + toCacheKey(String.valueOf(id)));
		TokenInfo tokenInfo = redisTokenTemplate.get("Token" + id);
		System.out.println(tokenInfo.getAccessToken());
		System.out.println(tokenInfo.getRefreshToken());
		String rt = cacheRepository.get(toCacheKey(String.valueOf(id)));
		TestDto dto = new TestDto(
				tokenInfo,
				rt
		);

		return dto;
	}


	private boolean isPasswordMatches(Member member, String enteredPassword){
		return member.isPasswordMatches(enteredPassword);
	}

	private TokenInfo generateToken(Long memberId, String enteredPassword){
		return jwtTokenProvider.generateToken(String.valueOf(memberId), enteredPassword);
	}

	private String toCacheKey(String memberId){
		return "RT:" + memberId;
	}
}
