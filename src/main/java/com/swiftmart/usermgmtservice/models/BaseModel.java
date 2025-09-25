package com.swiftmart.usermgmtservice.models;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.util.Date;

@Getter
@Setter
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
public abstract class BaseModel {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @CreatedDate
    private Date createdAt;
    @LastModifiedDate
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
