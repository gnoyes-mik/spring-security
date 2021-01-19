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

    public void encryptPassword(String encryptedPassword){
        this.password = encryptedPassword;
    }

    public void setInfoForTest() {
        this.userName = "test";
        this.password = "password";
        this.address = "Seoul";
        this.phoneNumber = "01012341234";
    }
}