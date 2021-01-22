package com.gnoyes.springsecurity.model.dto;

import com.gnoyes.springsecurity.enums.UserRole;
import com.gnoyes.springsecurity.model.entity.Account;
import lombok.Builder;
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
    String role;

    public AccountDto(Account entity) {
        this.id = entity.getId();
        this.userName = entity.getUserName();
        this.password = entity.getPassword();
        this.address = entity.getAddress();
        this.phoneNumber = entity.getPhoneNumber();
        this.role = entity.getRole();
    }

    @Builder
    public AccountDto(String userName, String role) {
        this.userName = userName;
        this.role = role;
    }

    public void encryptPassword(String encryptedPassword) {
        this.password = encryptedPassword;
    }

    public void setInfoForTest() {
        this.userName = "test";
        this.password = "password";
        this.address = "Seoul";
        this.phoneNumber = "01012341234";
        this.role = UserRole.NORMAL_USER.getRole();
    }
}