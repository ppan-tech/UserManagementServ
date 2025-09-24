package com.swiftmart.usermgmtservice.models;


import jakarta.persistence.Entity;
import jakarta.persistence.ManyToOne;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
@Entity(name = "tokens")
public class Token extends BaseModel{
    private String tokenValue;
    private Date expiryDate; // epoch time in milliseconds
    @ManyToOne
    private User user; // the user to whom this token belongs
}
