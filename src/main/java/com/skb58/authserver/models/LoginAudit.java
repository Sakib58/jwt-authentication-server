package com.skb58.authserver.models;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginAudit implements Serializable {
    private String ipAddress;
    private Date loginTime;
    //    private GeoLocation geoLocation;
    private DeviceInfo deviceInfo;
}
