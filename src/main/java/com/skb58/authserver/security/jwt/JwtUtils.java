package com.skb58.authserver.security.jwt;

import com.skb58.authserver.security.services.UserDetailsImpl;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class JwtUtils {
    @Value("${authentication.jwt.jwt-secret}")
    private String jwtSecret;
    @Value("${authentication.jwt.access-token-expiration-time-in-millis}")
    private Long jwtExpirationInMs;
    @Value("${authentication.jwt.refresh-token-expiration-time-in-millis}")
    private Long jwtRefreshTokenExpirationInMs;
    @Value("${authentication.jwt.refresh-token-remember-me-time-in-millis}")
    private Long jwtRefreshTokenRememberMeTimeInMs;


    public String generateJwtToken(Authentication authentication, TokenType tokenType, boolean isRememberMeClicked) {
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", roles);
        return Jwts.builder()
                .subject(userDetails.getUsername())
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime() + (
                        tokenType.equals(TokenType.ACCESS_TOKEN) ?
                                jwtExpirationInMs : (isRememberMeClicked ?
                                jwtRefreshTokenRememberMeTimeInMs : jwtRefreshTokenExpirationInMs ))
                        )
                )
                .claims(claims)
                .signWith(key())
                .compact();
    }
    public String generateJwtTokenFromRefreshToken(String refreshToken) {
        Collection<SimpleGrantedAuthority> authorities = getRolesFromToken(refreshToken);
        String username = getUsernameFromToken(refreshToken);
        List<String> roles = authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", roles);
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime() + jwtExpirationInMs))
                .claims(claims)
                .signWith(key())
                .compact();
    }
    public ResponseCookie generateCookieFromJwtToken(String name, String value, String path, long maxAgeInSec) {
        ResponseCookie cookie = ResponseCookie.from(name, value).path(path).maxAge(maxAgeInSec).httpOnly(true).build();
        return cookie;
    }
    private SecretKey key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64URL.decode(jwtSecret));
    }
    private Claims getAllClaims(String token) {
        if (token == null)
            return null;
        try {
            return Jwts.parser().verifyWith(key()).build().parseSignedClaims(token).getPayload();
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
    }
    private <T> T getClaimFromToken(String token, Function<Claims, T> claimsTFunction) {
        Claims claims = getAllClaims(token);
        return claimsTFunction.apply(claims);
    }
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }
    private Date getExpirationFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }
    public Collection<SimpleGrantedAuthority> getRolesFromToken(String token) {
        Claims claims = getAllClaims(token);
        List<String> roles = new ArrayList<>();
        if (claims != null)
            roles = claims.get("roles", List.class);

        if (roles.size() == 0) {
            return List.of();
        }

        return roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
    public boolean isTokenExpired(String token) {
        Date expiration = getExpirationFromToken(token);
        return expiration.before(new Date());
    }
    public boolean validateJwtToken(String token) {
        try {
            Jwts.parser().verifyWith(key()).build().parseSignedClaims(token);
            if (isTokenExpired(token)) {
                System.out.println("Token is expired!");
                return false;
            }
            return true;
        } catch (MalformedJwtException e) {
            System.out.println("Invalid JWT token: " + e.getMessage());
        } catch (ExpiredJwtException e) {
            System.out.println("JWT token is expired: " + e.getMessage());
        } catch (UnsupportedJwtException e) {
            System.out.println("JWT token is unsupported: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            System.out.println("JWT claims string is empty: " + e.getMessage());
        }
        return false;
    }
    public String parseJwt(HttpServletRequest request, String cookieName) {
        Cookie cookie = WebUtils.getCookie(request, cookieName);
        if (cookie == null)
            return null;
        return cookie.getValue();
    }
}
