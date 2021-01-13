package com.gnoyes.springsecurity.model;

import com.gnoyes.springsecurity.entity.Account;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Getter
@ToString
@NoArgsConstructor
public class AccountDto {
    long id;
    String userName;
    String password;
    String address;
    String phoneNumber;

    public AccountDto(Account entity) {
        this.id = entity.getId();
        this.userName = entity.getUserName();
        this.password = entity.getPassword();
        this.address = entity.getAddress();
        this.phoneNumber = entity.getPhoneNumber();
    }
}