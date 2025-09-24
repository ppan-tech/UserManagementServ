package com.swiftmart.usermgmtservice.models;

import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.MappedSuperclass;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
@MappedSuperclass
public abstract class BaseModel {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private Date createdAt;
    private Date lastUpdatedAt;
    //private boolean deleted;
    /*
        @GeneratedValue: This is an optional but very common annotation. It tells the persistence
                provider how the primary key value should be generated.
                In this example, GenerationType.IDENTITY means the database itself will auto-increment
                the id for new records. This is a common practice for primary keys, without this
                 strategy, runtime error will be there.
     */
}
