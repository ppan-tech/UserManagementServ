package com.swiftmart.usermgmtservice.models;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class Role extends BaseModel{
    private String value;// ADMIN, USER, MANAGER, TA, MENTOR, STUDENT etc.
}
