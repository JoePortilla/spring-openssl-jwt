package co.joeportilla.springjwtopenssl.services;

import co.joeportilla.springjwtopenssl.persistence.entities.UserEntity;
import co.joeportilla.springjwtopenssl.persistence.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;

    @Override
    public List<UserEntity> findAllUsers() {
        return userRepository.findAll();
    }
}
