package com.skb58.authserver.security.services;

import com.skb58.authserver.models.AccessToken;
import com.skb58.authserver.security.jwt.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.stereotype.Service;
import java.util.concurrent.TimeUnit;

@Service
public class AccessTokenService {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private RedisTemplate redisTemplate;

    @Value("${authentication.jwt.access-token-expiration-time-in-millis}")
    private Long jwtTokenExpirationInMs;

    private final String tokenPrefix = "access_token_";

    public void storeAccessTokenInRedis(AccessToken accessToken) {
        redisTemplate.opsForValue().set(tokenPrefix + accessToken.getUsername() +"_" + accessToken.getToken(), accessToken, jwtTokenExpirationInMs, TimeUnit.MILLISECONDS);
    }

    public boolean validateAccessToken(String token) {
        String username = jwtUtils.getUsernameFromToken(token);
        AccessToken accessToken = (AccessToken) redisTemplate.opsForValue().get(tokenPrefix + username + "_" + token);
        if (accessToken == null)
            return false;
        return jwtUtils.validateJwtToken(token) && !accessToken.isRevoked();
    }

    public void deleteAccessToken(String accessToken) {
        try {
            String username = jwtUtils.getUsernameFromToken(accessToken);
            redisTemplate.opsForValue().getOperations().delete(tokenPrefix + username + "_" + accessToken);
        } catch (Exception e) {
            throw new IllegalArgumentException(e.getMessage()) ;
        }
    }

    public void deleteAllAccessTokenByUsername(String username) {
        try {
            Cursor cursor = redisTemplate.opsForValue().getOperations().scan(ScanOptions.scanOptions().match(tokenPrefix + username + "*").build());
            while (cursor.hasNext())
                redisTemplate.opsForValue().getOperations().delete(cursor.next().toString());
        } catch (Exception e) {
            throw new IllegalArgumentException(e.getMessage());
        }
    }
}
