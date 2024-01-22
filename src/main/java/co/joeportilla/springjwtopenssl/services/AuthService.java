package co.joeportilla.springjwtopenssl.services;

import co.joeportilla.springjwtopenssl.persistence.entities.UserEntity;
import co.joeportilla.springjwtopenssl.services.models.dtos.LoginDTO;
import co.joeportilla.springjwtopenssl.services.models.dtos.ResponseDTO;

import java.util.HashMap;

public interface AuthService {
    HashMap<String, String> login(LoginDTO loginRequest) throws Exception;

    ResponseDTO register(UserEntity user) throws Exception;
}
