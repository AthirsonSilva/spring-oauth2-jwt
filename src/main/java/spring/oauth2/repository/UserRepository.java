package spring.oauth2.repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import spring.oauth2.document.User;

import java.util.Optional;

public interface UserRepository extends MongoRepository<User, String> {
    Optional<User> findByUsername(String username);
    boolean existsByUsername(String username);
}
