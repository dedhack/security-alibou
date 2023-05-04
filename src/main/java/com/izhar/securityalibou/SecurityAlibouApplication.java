package com.izhar.securityalibou;

import com.izhar.securityalibou.auth.AuthenticationService;
import com.izhar.securityalibou.auth.RegisterRequest;
import com.izhar.securityalibou.user.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import static com.izhar.securityalibou.user.Role.ADMIN;
import static com.izhar.securityalibou.user.Role.MANAGER;

@SpringBootApplication
public class SecurityAlibouApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityAlibouApplication.class, args);
    }

//    temp bean
    @Bean
    public CommandLineRunner commandLineRunner(
            AuthenticationService service
    ) {
        return args -> {
            var admin = RegisterRequest.builder()
                    .firstname("Admin")
                    .lastname("Admin")
                    .email("admin@mail.com")
                    .password("password")
                    .role(ADMIN)
                    .build();

            System.out.println("Admin token: " + service.register(admin).getAccessToken());

            var manager = RegisterRequest.builder()
                    .firstname("Admin")
                    .lastname("Admin")
                    .email("manager@mail.com")
                    .password("password")
                    .role(MANAGER)
                    .build();

            System.out.println("Admin token: " + service.register(admin).getAccessToken());
        };

    }


}
