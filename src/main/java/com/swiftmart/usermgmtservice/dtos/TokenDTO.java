package com.swiftmart.usermgmtservice.dtos;

import com.swiftmart.usermgmtservice.models.Role;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class TokenDTO {
    private String tokenValue;

    ///Note:These details are enough to validate a token and authorize a user.
}
