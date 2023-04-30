package com.izhar.securityalibou.token;

import com.izhar.securityalibou.user.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder // optional to use builder patterns
@NoArgsConstructor
@AllArgsConstructor
@Entity // necessary
public class Token {

    @Id
    @GeneratedValue
    private Integer id;

    private String token;

    @Enumerated(EnumType.STRING)
    private TokenType tokenType;

    private boolean expired;

    private boolean revoked;

    // each token belongs to 1 user
    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;
}
