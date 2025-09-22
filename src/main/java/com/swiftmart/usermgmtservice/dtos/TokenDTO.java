package com.swiftmart.usermgmtservice.dtos;

import com.swiftmart.usermgmtservice.models.Role;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class TokenDTO {
    private String tokenValue;
    private long expiryDate; // epoch time in milliseconds
    private String email; // the email of the user to whom this token belongs
    private List<Role> role; // the name of the user to whom this token belongs

    ///Note:These details are enough to validate a token and authorize a user.
}
