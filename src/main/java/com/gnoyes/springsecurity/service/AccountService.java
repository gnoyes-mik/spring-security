package com.gnoyes.springsecurity.service;

import com.gnoyes.springsecurity.entity.Account;
import com.gnoyes.springsecurity.enums.UserRole;
import com.gnoyes.springsecurity.exception.custom.DuplicateAccountException;
import com.gnoyes.springsecurity.model.AccountDto;
import com.gnoyes.springsecurity.repository.AccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AuthorizationServiceException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AccountService implements UserDetailsService {

    private final AccountRepository accountRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account entity = accountRepository.getByUserName(username);

        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(UserRole.NORMAL_USER.getRole()));

        return new User(entity.getUserName(), entity.getPassword(), authorities);
    }

    public AccountDto getAccountByName(String name) throws AuthorizationServiceException {
        Account entity = accountRepository.getByUserName(name);

        if (entity == null)
            throw new UsernameNotFoundException(name);

        return new AccountDto(entity);
    }

    public AccountDto signUpAccount(AccountDto signUpReq) throws Exception {
        if (accountRepository.getByUserName(signUpReq.getUserName()) != null)
            throw new DuplicateAccountException(signUpReq.getUserName() + " is already exist");

        signUpReq.encryptPassword(passwordEncoder.encode(signUpReq.getPassword()));

        Account entity = new Account();
        entity.updateAccount(signUpReq);

        return new AccountDto(accountRepository.save(entity));
    }

    public AccountDto updateAccount(long id, AccountDto updateReq) throws AuthorizationServiceException {
        Account entity = accountRepository.getById(id);

        if (entity == null)
            throw new UsernameNotFoundException(String.valueOf(id));

        updateReq.encryptPassword(passwordEncoder.encode(updateReq.getPassword()));

        entity.updateAccount(updateReq);

        return new AccountDto(accountRepository.save(entity));
    }
}
