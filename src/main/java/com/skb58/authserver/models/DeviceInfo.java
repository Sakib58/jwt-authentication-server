package com.skb58.authserver.models;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DeviceInfo implements Serializable {
    private String deviceName;
    private String browserName;
    private String browserVersion;
    private String osName;
    private String osVersion;
}
