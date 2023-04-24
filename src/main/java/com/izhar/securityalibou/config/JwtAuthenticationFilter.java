package com.izhar.securityalibou.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        // if no authHeader, the filter will pass the request along the filter chain
        if (authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }

        // if the header is present then, we extract the jwt token
        jwt = authHeader.substring(7); // extract the token from the header after "Bearer "
        userEmail = jwtService.extractUsername(jwt);// TODO: extract the userEmail from JWT Token
        // check userEmail is not null & if user has not been authenticated previously
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){
            // check user from DB
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            // check if token is valid
            if (jwtService.isTokenValid(jwt,userDetails)){
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                // now to update security context holder
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }

        }
        // finally, pass it along
        filterChain.doFilter(request, response);
    }
}
