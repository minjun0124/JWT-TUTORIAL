package tutorial.jwt.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tutorial.jwt.dto.UserDto;
import tutorial.jwt.entity.Authority;
import tutorial.jwt.entity.User;
import tutorial.jwt.repository.UserRepository;
import tutorial.jwt.util.SecurityUtil;

import java.util.Collections;
import java.util.Optional;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    // 생성자 주입
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * 회원가입을 수행하는 메소드
     */
    @Transactional
    public User signup(UserDto userDto) {
        // UserDto 로부터 username 을 가져와서 username 중복 가입을 막는다.
        if (userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).orElse(null) != null) {
            throw new RuntimeException("이미 가입되어 있는 유저입니다.");
        }

        // 권한 정보를 만든다.
        //빌더 패턴의 장점
        Authority authority = Authority.builder()
                .authorityName("ROLE_USER")         // 유저의 권한 정보
                .build();

        // 유저 정보를 만든다
        User user = User.builder()
                .username(userDto.getUsername())
                .password(passwordEncoder.encode(userDto.getPassword()))
                .nickname(userDto.getNickname())
                .authorities(Collections.singleton(authority))
                .activated(true)
                .build();

        // 유저, 권한 정보를 저장
        return userRepository.save(user);
    }

    // username 을 받아와서 해당하는 유저 객체와 권한 정보를 가져올 수 있다.
    @Transactional(readOnly = true)
    public Optional<User> getUserWithAuthorities(String username) {
        return userRepository.findOneWithAuthoritiesByUsername(username);
    }

    // 현재 SecurityContext 에 저장이 되어 있는 username 에 대한 유저객체와 권한정보를 가져올 수 있다.
    @Transactional(readOnly = true)
    public Optional<User> getMyUserWithAuthorities() {
        return SecurityUtil.getCurrentUsername().flatMap(userRepository::findOneWithAuthoritiesByUsername);
    }
}
