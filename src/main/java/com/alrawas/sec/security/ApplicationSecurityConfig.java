package com.alrawas.sec.security;

import com.alrawas.sec.jwt.JwtConfig;
import com.alrawas.sec.jwt.JwtTokenVerifier;
import com.alrawas.sec.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.SecretKey;

import static com.alrawas.sec.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) // disable if not using annothations but antm,atchers
public class ApplicationSecurityConfig {

    private final PasswordEncoder passwordEncoder;
    private final UserDetailsService userDetailsService;
    private final AuthenticationConfiguration authenticationConfiguration;

    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;

    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder,
                                     UserDetailsService userDetailsService,
                                     AuthenticationConfiguration authenticationConfiguration, SecretKey secretKey, JwtConfig jwtConfig) {
        this.passwordEncoder = passwordEncoder;
        this.userDetailsService = userDetailsService;
        this.authenticationConfiguration = authenticationConfiguration;
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }

//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http
//                .csrf().disable()
//                .authorizeHttpRequests((authz) -> authz
//                        .antMatchers(HttpMethod.GET, "/", "/index.html", "/css/*", "/js/*").permitAll()
//                        .antMatchers("/api/**").hasRole(STUDENT.name())
////                        .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
////                        .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
////                        .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
////                        .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
//                        .anyRequest().authenticated())
//                .formLogin()
//                .loginPage("/login").permitAll()
//                .defaultSuccessUrl("/courses", true)
//                .passwordParameter("password")
//                .usernameParameter("username")
//                .and().rememberMe()
//                .rememberMeParameter("remember-me")
//                .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
//                .key("somethingverysecured")
//                .and().logout()
//                .logoutUrl("/logout")
//                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
//                .clearAuthentication(true)
//                .invalidateHttpSession(true)
//                .deleteCookies("JSESSIONID", "remember-me")
//                .logoutSuccessUrl("/login")
//        ;
////                .httpBasic(withDefaults())
////                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//        ;
//
//        return http.build();
//    }


    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    // SecurityFilterChain for JWT Auth
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
                .addFilterAfter(new JwtTokenVerifier(jwtConfig, secretKey), JwtUsernameAndPasswordAuthenticationFilter.class)
                .authorizeHttpRequests(
                        (authz) -> authz
                                .antMatchers(HttpMethod.GET, "/", "/index.html", "/css/*", "/js/*").permitAll()
                                .antMatchers("/api/**").hasRole(STUDENT.name())
                                .anyRequest().authenticated()
                );

        return http.build();
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(userDetailsService);
        return provider;
    }


//    @Bean
//    public InMemoryUserDetailsManager userDetailsService(PasswordEncoder passwordEncoder) {
//
//        UserDetails user = User.builder()
//                .username("annasmith")
//                .password(passwordEncoder.encode("password"))
////                .roles(STUDENT.name()) // ROLE_STUDENT
//                .authorities(STUDENT.getGrantedAuthorities())
//                .build();
//
//        UserDetails lindaUser = User.builder()
//                .username("linda")
//                .password(passwordEncoder.encode("password123"))
////                .roles(ADMIN.name()) // ROLE_ADMIN
//                .authorities(ADMIN.getGrantedAuthorities())
//                .build();
//
//        UserDetails tomUser = User.builder()
//                .username("tom")
//                .password(passwordEncoder.encode("password123"))
////                .roles(ADMINTRAINEE.name()) // ROLE_ADMINTRAINEE
//                .authorities(ADMINTRAINEE.getGrantedAuthorities())
//                .build();
//
//        return new InMemoryUserDetailsManager(user, lindaUser, tomUser);
//    }


//    @Bean
//    public WebSecurityCustomizer webSecurityCustomizer() {
//        return (web) -> web.ignoring().antMatchers("/ignore1", "/ignore2");
//
//    }


}
