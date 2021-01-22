package com.gnoyes.springsecurity.service;

import com.gnoyes.springsecurity.component.security.JwtAuthToken;
import com.gnoyes.springsecurity.component.security.JwtAuthTokenProvider;
import com.gnoyes.springsecurity.enums.UserRole;
import com.gnoyes.springsecurity.exception.custom.DuplicateAccountException;
import com.gnoyes.springsecurity.model.dto.AccountDto;
import com.gnoyes.springsecurity.model.entity.Account;
import com.gnoyes.springsecurity.repository.AccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AccountService implements UserDetailsService {

    private final AccountRepository accountRepository;

    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtAuthTokenProvider jwtAuthTokenProvider;

    private final static long LOGIN_RETENTION_MINUTES = 30;


    public AccountDto login(String userName, String password) {
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(userName, password);

        //사용자 비밀번호 체크, 패스워드 일치하지 않는다면 Exception 발생 및 이후 로직 실행 안됨
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        //로그인 성공하면 인증 객체 생성 및 스프링 시큐리티 설정
        SecurityContextHolder.getContext().setAuthentication(authentication);


        String role = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .findFirst()
                .orElse(UserRole.UNKNOWN.getRole());

        AccountDto accountDto = AccountDto.builder()
                .userName(userName)
                .role(role)
                .build();

        return accountDto;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AccountDto entity = getAccountByName(username);

        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(UserRole.NORMAL_USER.getRole()));

        return new User(entity.getUserName(), entity.getPassword(), authorities);
    }

    public AccountDto getAccountByName(String userName) throws UsernameNotFoundException {
        Account entity = accountRepository.getByUserName(userName);

        if (entity == null)
            throw new UsernameNotFoundException(userName);

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

    public AccountDto updateAccount(long id, AccountDto updateReq) throws UsernameNotFoundException {
        Account entity = accountRepository.getById(id);

        if (entity == null)
            throw new UsernameNotFoundException(String.valueOf(id));

        updateReq.encryptPassword(passwordEncoder.encode(updateReq.getPassword()));

        entity.updateAccount(updateReq);

        return new AccountDto(accountRepository.save(entity));
    }

    public JwtAuthToken createAuthToken(AccountDto accountDto) {
        Date expiredDate = Date.from(LocalDateTime.now().plusMinutes(LOGIN_RETENTION_MINUTES).atZone(ZoneId.systemDefault()).toInstant());

        return jwtAuthTokenProvider.createAuthToken(accountDto.getUserName(), accountDto.getRole(), expiredDate);
    }
}
