package spring.oauth2.payload;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SignupDTO {
    private String username;
    private String password;
}
