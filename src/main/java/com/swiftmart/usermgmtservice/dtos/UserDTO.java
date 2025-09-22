package com.swiftmart.usermgmtservice.dtos;

import com.swiftmart.usermgmtservice.models.Role;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class UserDTO {
    private String name;
    private String email;
    private List<Role> roles;
}
