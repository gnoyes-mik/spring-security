package com.gnoyes.springsecurity.controller;

import com.gnoyes.springsecurity.model.AccountDto;
import com.gnoyes.springsecurity.service.AccountService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class AccountController {

    final private AccountService accountService;

    @GetMapping("/api/user")
    public ResponseEntity<AccountDto> getAccount(@RequestParam(name = "name") String name) {
        return new ResponseEntity<>(accountService.getAccountByName(name), HttpStatus.OK);
    }

    @PostMapping("/api/user")
    public ResponseEntity<AccountDto> createAccount(@RequestBody AccountDto signUpReq) throws Exception {
        return new ResponseEntity<>(accountService.signUpAccount(signUpReq), HttpStatus.CREATED);
    }

    @PutMapping("/api/user")
    public ResponseEntity<AccountDto> updateAccount(@RequestParam(name = "id") long id,
                                                    @RequestBody AccountDto updateReq) {
        return new ResponseEntity<>(accountService.updateAccount(id, updateReq), HttpStatus.OK);
    }

    @GetMapping("/test/create")
    public ResponseEntity<AccountDto> createTestId() throws Exception {
        AccountDto testAccount = new AccountDto();
        testAccount.setInfoForTest();
        return new ResponseEntity<>(accountService.signUpAccount(testAccount), HttpStatus.OK);
    }
}
