package tutorial.jwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tutorial.jwt.entity.Authority;

public interface AuthorityRepository extends JpaRepository<Authority, String> {
}
