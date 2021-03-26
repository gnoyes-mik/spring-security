package com.gnoyes.springsecurity.service;

import com.gnoyes.springsecurity.enums.UserRole;
import com.gnoyes.springsecurity.model.entity.Account;
import com.gnoyes.springsecurity.repository.AccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthenticationService implements UserDetailsService {

    private final AccountRepository accountRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account entity = accountRepository.getByUserName(username);

        if (entity == null)
            throw new UsernameNotFoundException(username);


        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(UserRole.NORMAL_USER.getRole()));

        return new User(entity.getUserName(), entity.getPassword(), authorities);
    }
}
