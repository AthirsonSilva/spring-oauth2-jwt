package spring.oauth2.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import spring.oauth2.document.User;
import spring.oauth2.payload.LoginDTO;
import spring.oauth2.payload.SignupDTO;
import spring.oauth2.payload.TokenDTO;
import spring.oauth2.security.TokenGenerator;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final UserDetailsManager userDetailsManager;
    private final TokenGenerator tokenGenerator;
    private final DaoAuthenticationProvider daoAuthenticationProvider;
    @SuppressWarnings("SpringQualifierCopyableLombok")
    @Qualifier("jwtRefreshTokenAuthProvider")
    private final JwtAuthenticationProvider refreshTokenAuthProvider;

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

    @PostMapping("/login")
    public ResponseEntity<TokenDTO> login(@RequestBody LoginDTO request) {
        Authentication authentication = daoAuthenticationProvider.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        return ResponseEntity.ok(tokenGenerator.createToken(authentication));
    }

    @PostMapping("/token")
    public ResponseEntity<?> token(@RequestBody TokenDTO request) {
        Authentication authentication = refreshTokenAuthProvider.authenticate(
                new BearerTokenAuthenticationToken(request.getRefreshToken())
        );
        Jwt jwt = (Jwt) authentication.getPrincipal();

        return ResponseEntity.ok(
                Map.of(
                        "accessToken", jwt.getTokenValue(),
                        "refreshToken", request.getRefreshToken(),
                        "userDetails", jwt.getClaims().get("userDetails")
                )
        );
    }
}
