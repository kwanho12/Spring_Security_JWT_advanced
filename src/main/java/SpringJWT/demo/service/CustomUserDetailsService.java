package SpringJWT.demo.service;

import SpringJWT.demo.dto.CustomUserDetails;
import SpringJWT.demo.entity.UserEntity;
import SpringJWT.demo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String userId) throws UsernameNotFoundException {

        UserEntity userData = userRepository.findByUserId(userId);

        if(userData != null) {
            return new CustomUserDetails(userData);
        }
        return null;
    }
}
