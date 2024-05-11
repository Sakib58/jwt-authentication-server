package com.skb58.authserver.models;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken implements Serializable {
    private String username;
    private String token;
    private boolean isBlacklisted;
    private boolean isRevoked;
    private boolean isInvalidated;
    private LoginAudit loginAudit;
}
