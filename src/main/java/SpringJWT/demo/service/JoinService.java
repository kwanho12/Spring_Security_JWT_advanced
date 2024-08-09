package SpringJWT.demo.service;

import SpringJWT.demo.dto.JoinDTO;
import SpringJWT.demo.entity.UserEntity;
import SpringJWT.demo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public void joinProcess(JoinDTO joinDTO) {

        String userId = joinDTO.getUserId();
        String password = joinDTO.getPassword();

        Boolean isExists = userRepository.existsByUserId(userId);

        if (isExists) {
            throw new RuntimeException("이미 존재하는 아이디");
        }

        UserEntity data = new UserEntity();
        data.setUserId(userId);
        data.setPassword(bCryptPasswordEncoder.encode(password));
        data.setRole("ROLE_ADMIN");

        userRepository.save(data);
    }
}
