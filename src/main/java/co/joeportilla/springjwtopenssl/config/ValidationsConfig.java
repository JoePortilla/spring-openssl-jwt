package co.joeportilla.springjwtopenssl.config;

import co.joeportilla.springjwtopenssl.services.models.validation.UserValidations;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ValidationsConfig {

    @Bean
    public UserValidations userValidations() {
        return new UserValidations();
    }
}