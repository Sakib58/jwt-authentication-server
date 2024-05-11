package com.skb58.authserver.controllers;

import com.skb58.authserver.models.LoginAudit;
import com.skb58.authserver.payloads.request.ChangePasswordRequest;
import com.skb58.authserver.services.AuthService;
import com.skb58.authserver.services.UserAuthService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/user")
public class UserAuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private UserAuthService userAuthService;

    @Value("${authentication.cookie.access-token-name}")
    String accessTokenCookieName;

    @Value("${authentication.cookie.refresh-token-name}")
    String refreshTokenCookieName;

    @Value("${authentication.jwt.access-token-expiration-time-in-millis}")
    private Long jwtExpirationInMs;

    @Value("${authentication.jwt.refresh-token-expiration-time-in-millis}")
    private Long jwtRefreshTokenExpirationInMs;

    @Value("${authentication.jwt.refresh-token-remember-me-time-in-millis}")
    private Long jwtRefreshTokenRememberMeTimeInMs;

    @PostMapping("/sign-out")
    public ResponseEntity<?> signOut(HttpServletRequest request) {
        userAuthService.signOut(request, accessTokenCookieName, refreshTokenCookieName);
        ResponseCookie accessTokenCookie = authService.generateCookieFromJwtToken(accessTokenCookieName, null, "/api", 0);
        ResponseCookie refreshTokenCookie = authService.generateCookieFromJwtToken(refreshTokenCookieName, null, "/api", 0);
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, accessTokenCookie.toString())
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                .body("Successfully signed out from the system!");
    }

    @PostMapping("/sign-out-from-all-device")
    public ResponseEntity<?> signOutFromAllDevice(HttpServletRequest request) {
        userAuthService.signOutFromAllDevices(request, accessTokenCookieName);
        ResponseCookie accessTokenCookie = authService.generateCookieFromJwtToken(accessTokenCookieName, null, "/api", 0);
        ResponseCookie refreshTokenCookie = authService.generateCookieFromJwtToken(refreshTokenCookieName, null, "/api", 0);
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, accessTokenCookie.toString())
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                .body("Successfully signed out from the system!");
    }

    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(
            @RequestBody ChangePasswordRequest changePasswordRequest,
            HttpServletRequest request
    ) {
        String message = userAuthService.changePassword(changePasswordRequest, request);
        if (message.startsWith("Error:"))
            return ResponseEntity.badRequest().body(message);
        ResponseCookie accessTokenCookie = authService.generateCookieFromJwtToken(accessTokenCookieName, null, "/api", 0);
        ResponseCookie refreshTokenCookie = authService.generateCookieFromJwtToken(refreshTokenCookieName, null, "/api", 0);
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, accessTokenCookie.toString())
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                .body("Password changed successfully!");
    }

    @GetMapping("/get-logged-in-devices")
    public ResponseEntity<?> getAllLoggedInDevices(HttpServletRequest request) {
        List<LoginAudit> loginAudits = userAuthService.getLoggedInDevices(request, refreshTokenCookieName);
        return ResponseEntity.ok().body(loginAudits);
    }
}
