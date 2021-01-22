package com.gnoyes.springsecurity.repository;

import com.gnoyes.springsecurity.model.entity.Account;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AccountRepository extends JpaRepository<Account, Long> {
    Account getById(long id);
    Account getByUserName(String username);
}
