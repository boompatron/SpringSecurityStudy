package com.example.springsecuritystudy.domain;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {

	private final MemberRepository memberRepository;
	private final PasswordEncoder passwordEncoder;

	@Override
	public UserDetails loadUserByUsername(String memberId) throws UsernameNotFoundException {
		return memberRepository.findById(Long.parseLong(memberId))
				.map(this::createUserDetails)
				.orElseThrow(() -> new UsernameNotFoundException("해당하는 유저는 없습니다...!!"));
	}

	// @Override
	// public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
	// 	return memberRepository.findByMemberId(username)
	// 			.map(this::createUserDetails)
	// 			.orElseThrow(() -> new UsernameNotFoundException("해당하는 유저는 없습니다...!!"));
	// }

	// 해당하는 User 의 데이터가 존재한다면 UserDetails 객체로 만들어서 리턴
	private UserDetails createUserDetails(Member member) {
		return User.builder()
				.username(member.getUsername())
				.password(member.getPassword())
				.roles(member.getRoles().toArray(new String[0]))
				.build();
	}
}
