package SpringJWT.demo.repository;

import SpringJWT.demo.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

    Boolean existsByUserId(String userId);

    UserEntity findByUserId(String userId);
}
