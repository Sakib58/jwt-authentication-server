package com.skb58.authserver.security.services;

import com.skb58.authserver.models.DeviceInfo;
import com.skb58.authserver.models.LoginAudit;
import com.skb58.authserver.models.RefreshToken;
import com.skb58.authserver.security.jwt.JwtUtils;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.stereotype.Service;
import ua_parser.Client;
import ua_parser.Parser;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Service
public class RefreshTokenService {
    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private RedisTemplate redisTemplate;

    @Value("${authentication.jwt.refresh-token-expiration-time-in-millis}")
    private Long jwtRefreshTokenExpirationInMs;

    @Value("${authentication.jwt.refresh-token-remember-me-time-in-millis}")
    private Long jwtRefreshTokenRememberMeTimeInMs;

    private final String tokenPrefix = "refresh_token_";

    public boolean validateRefreshToken(String token) {
        String username = jwtUtils.getUsernameFromToken(token);
        RefreshToken refreshToken = null;
        try {
            refreshToken = (RefreshToken) redisTemplate.opsForValue().get(tokenPrefix + username + "_" + token);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
        if (refreshToken == null)
            return false;
        return jwtUtils.validateJwtToken(token) &&
                !(refreshToken.isBlacklisted() || refreshToken.isInvalidated() || refreshToken.isRevoked());
    }

    public String createNewAccessToken(String refreshToken) {
        return jwtUtils.generateJwtTokenFromRefreshToken(refreshToken);
    }

    public void storeRefreshTokenInRedis(RefreshToken refreshToken, boolean isRememberMeClicked) {
        String refreshTokenField = tokenPrefix + refreshToken.getUsername() + "_" + refreshToken.getToken();
        Long expirationInSeconds = isRememberMeClicked ? jwtRefreshTokenRememberMeTimeInMs : jwtRefreshTokenExpirationInMs;
        try {
            redisTemplate.opsForValue().set(refreshTokenField, refreshToken, expirationInSeconds, TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    public void deleteRefreshToken(String refreshToken) {
        try {
            String username = jwtUtils.getUsernameFromToken(refreshToken);
            redisTemplate.opsForValue().getOperations().delete(tokenPrefix + username + "_" + refreshToken);
        } catch (Exception e) {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

    public void deleteAllRefreshTokenByUsername(String username) {
        try {
            Cursor c = redisTemplate.scan(ScanOptions.scanOptions().match(tokenPrefix + username + "*").build());
            while (c.hasNext())
                redisTemplate.opsForValue().getOperations().delete(c.next().toString());
        } catch (Exception e) {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

    public List<RefreshToken> getAllRefreshTokenByUsername(String username) {
        List<RefreshToken> refreshTokens = new ArrayList<>();
        try {
            Cursor c = redisTemplate.scan(ScanOptions.scanOptions().match(tokenPrefix + username + "*").build());
            while (c.hasNext()) {
                refreshTokens.add((RefreshToken) redisTemplate.opsForValue().get(c.next()));
            }
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
        return refreshTokens;
    }
    public RefreshToken addLoginAuditToRefreshToken(RefreshToken refreshToken, HttpServletRequest request) {
        String userAgent = request.getHeader("user-agent");
        Parser parser = new Parser();
        Client client = parser.parse(userAgent);
        DeviceInfo deviceInfo = DeviceInfo.builder()
                .deviceName(client.device.family)
                .browserName(client.userAgent.family)
                .browserVersion(client.userAgent.major + "." + client.userAgent.minor)
                .osName(client.os.family)
                .osVersion(client.os.major + "." + client.os.minor)
                .build();
        refreshToken.setLoginAudit(
                LoginAudit.builder()
                        .deviceInfo(deviceInfo)
                        .ipAddress(request.getRemoteAddr())
                        .loginTime(new Date())
                        .build()
        );
        return refreshToken;
    }

    public void revokeUserAccessByUsername(String username) {
        try {
            Cursor c = redisTemplate.scan(ScanOptions.scanOptions().match(tokenPrefix + username + "*").build());
            while (c.hasNext()) {
                RefreshToken refreshToken = (RefreshToken) redisTemplate.opsForValue().get(c.next());
                refreshToken.setRevoked(true);
                redisTemplate.opsForValue().set(tokenPrefix + username + "_" + refreshToken.getToken(), refreshToken);
            }
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
    }
}