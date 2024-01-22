package co.joeportilla.springjwtopenssl.services.models.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ResponseDTO {
    private int numOfErrors;
    private String message;
}
