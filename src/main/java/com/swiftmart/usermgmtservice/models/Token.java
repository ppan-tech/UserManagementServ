package com.swiftmart.usermgmtservice.models;


import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
public class Token extends BaseModel{
    private String tokenValue;
    private Date expiryDate; // epoch time in milliseconds
    private User user; // the user to whom this token belongs
}
