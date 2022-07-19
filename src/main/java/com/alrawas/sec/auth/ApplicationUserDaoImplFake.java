package com.alrawas.sec.auth;

import com.google.common.collect.Lists;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.alrawas.sec.security.ApplicationUserRole.*;

// use this to fetch user from db
@Repository("fake")
public class ApplicationUserDaoImplFake implements ApplicationUserDao {

    private final PasswordEncoder passwordEncoder;

    public ApplicationUserDaoImplFake(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectAppliactionUserByUsername(String username) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
                new ApplicationUser(
                        STUDENT.getGrantedAuthorities(),
                        passwordEncoder.encode("password"),
                        "annasmith",
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        ADMIN.getGrantedAuthorities(),
                        passwordEncoder.encode("password"),
                        "linda",
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        ADMINTRAINEE.getGrantedAuthorities(),
                        passwordEncoder.encode("password"),
                        "tom",
                        true,
                        true,
                        true,
                        true
                )
        );

        return applicationUsers;
    }

}
