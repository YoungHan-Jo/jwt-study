package com.example.jwt.auth;

import com.example.jwt.model.User;
import com.example.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


// http://localhost:8080/login 요청이 오면 동작하지만, formLogin은 disable로 했기때문에 동작하지 않음
// -> 필터를 만들어야함
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("principalDetailsService의 loadUserByUsername()");
        User userEntity = userRepository.findByUsername(username);
        return new PrincipalDetails(userEntity);
    }
}
