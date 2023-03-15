package spring.oauth2.payload;

import lombok.Builder;
import lombok.Data;
import spring.oauth2.document.User;

@Data
@Builder
public class UserDTO {
    private String id;
    private String username;

    public static UserDTO from(User user) {
        return builder()
                .id(user.getId())
                .username(user.getUsername())
                .build();
    }
}
