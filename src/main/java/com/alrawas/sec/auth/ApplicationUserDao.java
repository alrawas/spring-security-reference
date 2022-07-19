package com.alrawas.sec.auth;

import java.util.Optional;

public interface ApplicationUserDao {

    Optional<ApplicationUser> selectAppliactionUserByUsername(String username);

}
