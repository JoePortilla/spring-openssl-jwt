package co.joeportilla.springjwtopenssl.services;

import co.joeportilla.springjwtopenssl.persistence.entities.UserEntity;

import java.util.List;

public interface UserService {
    List<UserEntity> findAllUsers();
}
