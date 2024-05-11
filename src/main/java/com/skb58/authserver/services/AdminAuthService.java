package com.skb58.authserver.services;

import com.skb58.authserver.security.services.RefreshTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AdminAuthService {

    @Autowired
    private RefreshTokenService refreshTokenService;

    public String revokeUserAccessByUsername(String username) {
        refreshTokenService.revokeUserAccessByUsername(username);
        return "Revoked all access for this user: " + username;
    }
}
