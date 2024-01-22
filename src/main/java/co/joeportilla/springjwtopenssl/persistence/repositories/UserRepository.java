package co.joeportilla.springjwtopenssl.persistence.repositories;

import co.joeportilla.springjwtopenssl.persistence.entities.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository
        extends JpaRepository<UserEntity, Long> {
    Optional<UserEntity> findByEmail(String email);
}
