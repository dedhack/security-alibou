package com.izhar.securityalibou.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Integer> {

    // to get all the valid tokens for a specific user
    @Query("""
            SELECT t from Token t inner join User u on t.user.id = u.id
            WHERE u.id = :id and (t.expired = false or t.revoked = false)
            """)
    List<Token> findAllValidTokensByUser(Integer id);

    // finding token by the token itself
    Optional<Token> findByToken(String token);

}
