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
public class GeoLocation implements Serializable {
    private String city;
    private String country;
    private Long latitude;
    private Long longitude;
}
