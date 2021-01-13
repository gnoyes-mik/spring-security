package com.gnoyes.springsecurity.service;

import com.gnoyes.springsecurity.entity.Account;
import com.gnoyes.springsecurity.exception.custom.DuplicateAccountException;
import com.gnoyes.springsecurity.exception.custom.NotExistAccountException;
import com.gnoyes.springsecurity.model.AccountDto;
import com.gnoyes.springsecurity.repository.AccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AccountService {
    private final AccountRepository accountRepository;

    public AccountDto getAccountByName(String name) throws Exception {
        Account entity = accountRepository.getByUserName(name);

        if (entity == null)
            throw new NotExistAccountException(name + " is not exist");

        return new AccountDto(entity);
    }

    public AccountDto signUpAccount(AccountDto signUpReq) throws Exception {
        if (accountRepository.getByUserName(signUpReq.getUserName()) != null)
            throw new DuplicateAccountException(signUpReq.getUserName() + " is already exist");

        Account entity = new Account();
        entity.updateAccount(signUpReq);

        return new AccountDto(accountRepository.save(entity));
    }

    public AccountDto updateAccount(long id, AccountDto updateReq) throws Exception {
        Account entity = accountRepository.getById(id);

        if (entity == null)
            throw new NotExistAccountException(id + " user is not exist");

        entity.updateAccount(updateReq);

        return new AccountDto(accountRepository.save(entity));
    }
}
