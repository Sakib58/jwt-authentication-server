package com.skb58.authserver.services;

import com.skb58.authserver.models.*;
import com.skb58.authserver.payloads.request.LoginRequest;
import com.skb58.authserver.payloads.request.SignupRequest;
import com.skb58.authserver.payloads.response.JwtResponse;
import com.skb58.authserver.repositories.RoleRepository;
import com.skb58.authserver.repositories.UserRepository;
import com.skb58.authserver.security.jwt.JwtUtils;
import com.skb58.authserver.security.jwt.TokenType;
import com.skb58.authserver.security.services.AccessTokenService;
import com.skb58.authserver.security.services.RefreshTokenService;
import com.skb58.authserver.security.services.UserDetailsImpl;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class AuthService {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private AccessTokenService accessTokenService;

    public JwtResponse signIn (LoginRequest loginRequest, HttpServletRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication, TokenType.ACCESS_TOKEN, false);
        accessTokenService.storeAccessTokenInRedis(
                AccessToken.builder()
                        .username(loginRequest.getUsername())
                        .token(jwt)
                        .isRevoked(false)
                        .build()
        );

        String refreshToken = jwtUtils.generateJwtToken(authentication, TokenType.REFRESH_TOKEN, loginRequest.isRememberMeClicked());

        refreshTokenService.storeRefreshTokenInRedis(
                refreshTokenService.addLoginAuditToRefreshToken(RefreshToken
                        .builder()
                        .username(loginRequest.getUsername())
                        .token(refreshToken)
                        .isBlacklisted(false)
                        .isInvalidated(false)
                        .isRevoked(false)
                        .build(), request),
                loginRequest.isRememberMeClicked()
        );

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        return new JwtResponse(
                jwt,
                refreshToken,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles
        );
    }

    public ResponseCookie generateCookieFromJwtToken(String accessTokenCookieName, String accessToken, String path, long expirationInSec) {
        return jwtUtils.generateCookieFromJwtToken( accessTokenCookieName, accessToken, path, expirationInSec );
    }

    public String signUp(SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return "Error: Username is already taken!";
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return "Error: Email is already in use!";
        }

        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);

                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);
        return "User registered successfully!";
    }

    public String refreshToken(HttpServletRequest request, String refreshTokenCookieName) {
        String refreshToken = jwtUtils.parseJwt(request, refreshTokenCookieName);
        if (!refreshTokenService.validateRefreshToken(refreshToken))
            return "Error: Refresh token isn't valid! Please login again!";
        String accessToken = refreshTokenService.createNewAccessToken(refreshToken);
        accessTokenService.storeAccessTokenInRedis(
                AccessToken.builder()
                        .token(accessToken)
                        .username(jwtUtils.getUsernameFromToken(accessToken))
                        .isRevoked(false)
                        .build()
        );
        return accessToken;
    }
}
