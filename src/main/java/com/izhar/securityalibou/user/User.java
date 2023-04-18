package com.izhar.securityalibou.user;

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
@Table(name = "_user")
public class User {

    @Id
    @GeneratedValue
    private Integer id;

    private String firstname;
    private String lastname;
    private String email;
    private String password;

}
