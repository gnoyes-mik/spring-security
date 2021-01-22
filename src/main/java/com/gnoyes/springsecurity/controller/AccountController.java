package com.gnoyes.springsecurity.controller;

import com.gnoyes.springsecurity.component.security.JwtAuthToken;
import com.gnoyes.springsecurity.model.dto.AccountDto;
import com.gnoyes.springsecurity.model.dto.LoginRequestDto;
import com.gnoyes.springsecurity.model.dto.LoginSuccess;
import com.gnoyes.springsecurity.service.AccountService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class AccountController {

    final private AccountService accountService;

    @PostMapping("/api/login")
    public ResponseEntity<LoginSuccess> login(@RequestBody LoginRequestDto loginRequestDto) throws Exception {
        AccountDto accountDto = accountService.login(loginRequestDto.getUserName(), loginRequestDto.getPassword());

        JwtAuthToken jwtAuthToken = accountService.createAuthToken(accountDto);

        return new ResponseEntity<>(
                LoginSuccess.builder()
                        .userName(accountDto.getUserName())
                        .role(accountDto.getRole())
                        .message("Login Success")
                        .jwtAuthToken(jwtAuthToken.getToken())
                        .build()
                , HttpStatus.OK);
    }

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
