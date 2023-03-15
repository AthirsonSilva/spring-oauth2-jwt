package spring.oauth2.security;

import org.bson.json.StrictJsonWriter;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import spring.oauth2.document.User;

import java.util.Collections;

@Component
public class JwtToUserConverter implements Converter<Jwt, UsernamePasswordAuthenticationToken> {
    @Override
    public UsernamePasswordAuthenticationToken convert(Jwt source) {
        User user = new User();
        user.setId(source.getSubject());

        return new UsernamePasswordAuthenticationToken(user, source, Collections.emptyList());
    }
}
