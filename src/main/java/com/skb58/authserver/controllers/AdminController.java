package com.skb58.authserver.controllers;

import com.skb58.authserver.services.AdminAuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequestMapping("/api/admin")
@RestController
public class AdminController {

    @Autowired
    private AdminAuthService adminAuthService;

    @GetMapping("/revoke-access")
    public ResponseEntity<?> revokeUserAccess(@RequestParam String username) {
        String message = adminAuthService.revokeUserAccessByUsername(username);
        return ResponseEntity.ok().body(message);
    }
}
