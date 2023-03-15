package spring.oauth2.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import spring.oauth2.document.User;
import spring.oauth2.payload.SignupDTO;
import spring.oauth2.payload.TokenDTO;
import spring.oauth2.security.TokenGenerator;

import java.util.Collections;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final UserDetailsManager userDetailsManager;
    private final TokenGenerator tokenGenerator;

    @PostMapping("/register")
    public ResponseEntity<TokenDTO> register(@RequestBody SignupDTO request) {
        User user = new User(
                request.getUsername(),
                request.getPassword()
        );

        userDetailsManager.createUser(user);

        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(
                user,
                user.getPassword(),
                Collections.emptyList()
        );

        return ResponseEntity.ok(tokenGenerator.createToken(authentication));
    }
}
