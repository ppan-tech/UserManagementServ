package com.swiftmart.usermgmtservice.dtos;

import com.swiftmart.usermgmtservice.models.Role;
import com.swiftmart.usermgmtservice.models.Token;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class TokenDTO {
    private String tokenValue;

    ///Note:These details are enough to validate a token and authorize a user.

    public static TokenDTO from(Token token) {
        if (token == null) {
            return null;
        }

        TokenDTO tokenDTO = new TokenDTO();
        tokenDTO.setTokenValue(token.getTokenValue());
        return tokenDTO;
    }
}
