package hello;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.kerberos.authentication.KerberosServiceAuthenticationProvider;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    Logger logger = LoggerFactory.getLogger(WebSecurityConfig.class);

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/", "/home").permitAll()
                .anyRequest().authenticated()
                .and()
            .formLogin()
                .loginPage("/login")
                .permitAll()
                .and()
            .logout()
                .permitAll()
            .and()
        .addFilterBefore(localhostAuthFilter(authenticationManager()), BasicAuthenticationFilter.class)
        ;
    }

    /**
     * This ensures a global configuration for the security of the application.
     *
     * @param auth
     * @param kerbServiceProvider
     */
    @Autowired
    protected void configureGlobal(AuthenticationManagerBuilder auth,
                                   LocalhostAuthProvider localhostAuthProvider
    //                               KerberosServiceAuthenticationProvider kerbServiceProvider
    ) {
        auth
                .authenticationProvider(localhostAuthProvider);
                //.authenticationProvider(kerbServiceProvider);
    }

    @Bean
    public LocalhostAuthProvider localhostAuthProvider() {
        LocalhostAuthProvider localhostAuthProvider = new LocalhostAuthProvider();
        localhostAuthProvider.setUserDetailsService(userDetailsService());
        return localhostAuthProvider;
    }

    @Bean
    public LocalhostAuthFilter localhostAuthFilter(AuthenticationManager authenticationManager) {
        LocalhostAuthFilter localhostAuthFilter = new LocalhostAuthFilter();
        localhostAuthFilter.setAuthenticationManager(authenticationManager);
        return localhostAuthFilter;
    }

    @Bean
    @Override
    public UserDetailsService userDetailsService() {
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                logger.info("user detail:" + username);
                return User.withDefaultPasswordEncoder().username(username).password("notUsed").roles("ROLD_USER").build();
//                return new User(username, "password", true, true, true, true,
//                        AuthorityUtils.createAuthorityList("ROLE_USER"));
            }
        };
//        UserDetails user =
//             User.withDefaultPasswordEncoder()
//                .username("user")
//                .password("password")
//                .roles("USER")
//                .build();
//
//        return new InMemoryUserDetailsManager(user);
    }
}