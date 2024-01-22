package co.joeportilla.springjwtopenssl.services;

import co.joeportilla.springjwtopenssl.persistence.entities.UserEntity;
import co.joeportilla.springjwtopenssl.persistence.repositories.UserRepository;
import co.joeportilla.springjwtopenssl.services.models.dtos.LoginDTO;
import co.joeportilla.springjwtopenssl.services.models.dtos.ResponseDTO;
import co.joeportilla.springjwtopenssl.services.models.validation.UserValidations;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final UserRepository userRepository;
    private final JWTUtilityService jwtUtilityService;
    private final UserValidations userValidations;

    private boolean verifyPassword(String enteredPassword, String storedPassword) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        return encoder.matches(enteredPassword, storedPassword);
    }

    @Override
    public HashMap<String, String> login(LoginDTO loginRequest) throws Exception {
        try {
            HashMap<String, String> jwt = new HashMap<>();
            // Find the user in the db
            Optional<UserEntity> user = userRepository.findByEmail(loginRequest.getEmail());
            // Is the user is not registered
            if (user.isEmpty()) {
                jwt.put("error", "User not registered!");
                return jwt;
            }
            // Verify the password
            if (verifyPassword(loginRequest.getPassword(), user.get().getPassword())) {
                // Generate the jwt if the password is correct
                jwt.put("jwt", jwtUtilityService.generateJWT(user.get().getId()));
            } else {
                jwt.put("error", "Authentication failed");
            }
            return jwt;
        }
        catch (IllegalArgumentException e) {
            System.err.println("Error generating JWT: " + e.getMessage());
            throw new Exception("Error generating JWT", e);
        }
        catch (Exception e) {
            System.err.println("Unknown error: " + e.toString());
            throw new Exception("Unknown error", e);
        }
    }

    @Override
    public ResponseDTO register(UserEntity user) throws Exception {
        try {
            ResponseDTO response = userValidations.validate(user);

            if (response.getNumOfErrors() > 0) {
                return response;
            }

            List<UserEntity> getAllUsers = userRepository.findAll();

            for (UserEntity repeatFields : getAllUsers) {
                if (repeatFields != null) {
                    response.setMessage("User already exists!");
                    return response;
                }
            }

            BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
            user.setPassword(encoder.encode(user.getPassword()));
            userRepository.save(user);
            response.setMessage("User created successfully!");
            return response;
        }
        catch (Exception e) {
            throw new Exception(e.getMessage());
        }
    }
}
