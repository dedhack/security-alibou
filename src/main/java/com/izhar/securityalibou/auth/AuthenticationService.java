package com.izhar.securityalibou.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.izhar.securityalibou.config.JwtService;
import com.izhar.securityalibou.token.Token;
import com.izhar.securityalibou.token.TokenRepository;
import com.izhar.securityalibou.token.TokenType;
import com.izhar.securityalibou.user.Role;
import com.izhar.securityalibou.user.User;
import com.izhar.securityalibou.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;

    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        var savedUser = userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        saveUserToken(savedUser, jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        // if username and password correct
        var user = userRepository.findByEmail(request.getEmail()).orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);

        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }
    private void revokeAllUserTokens(User user) {
        var validUserTokens = tokenRepository.findAllValidTokensByUser(user.getId());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(t->{
            t.setExpired(true);
            t.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    private void saveUserToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .revoked(false)
                .expired(false)
                .build();
        tokenRepository.save(token);
    }

    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;

        // if no authHeader, the filter will pass the request along the filter chain
        if (authHeader == null || !authHeader.startsWith("Bearer ")){
            return;
        }

        // if the header is present then, we extract the jwt token
        refreshToken = authHeader.substring(7); // extract the token from the header after "Bearer "
        userEmail = jwtService.extractUsername(refreshToken);// TODO: extract the userEmail from JWT Token
        // check userEmail is not null & if user has not been authenticated previously
        if (userEmail != null){
            // check user from DB
            var userDetails = this.userRepository.findByEmail(userEmail).orElseThrow();

            // check if token is valid
            if (jwtService.isTokenValid(refreshToken,userDetails)){
                var accessToken = jwtService.generateToken(userDetails); // create access token
                revokeAllUserTokens(userDetails);
                saveUserToken(userDetails, accessToken);
                var authResponse = AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken) // reuse the same refresh token, unless expired
                        .build();

                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }

        }
    }
}
