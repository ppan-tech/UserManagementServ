package com.swiftmart.usermgmtservice.models;

import jakarta.persistence.Entity;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@Entity(name = "roles")
public class Role extends BaseModel{
    private String value;// ADMIN, USER, MANAGER, TA, MENTOR, STUDENT etc.
}
