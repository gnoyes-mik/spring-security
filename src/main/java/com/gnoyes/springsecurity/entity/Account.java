package com.gnoyes.springsecurity.entity;

import com.gnoyes.springsecurity.model.AccountDto;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import javax.persistence.*;

@Entity
@Table(name = "account", indexes = {@Index(columnList = "userName")})
@Getter
@ToString
@NoArgsConstructor
@AllArgsConstructor
public class Account {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String userName;

    private String password;

    private String address;

    private String phoneNumber;

    public void updateAccount(AccountDto dto) {
        this.userName = dto.getUserName();
        this.password = dto.getPassword();
        this.address = dto.getAddress();
        this.phoneNumber = dto.getPhoneNumber();
    }
}
