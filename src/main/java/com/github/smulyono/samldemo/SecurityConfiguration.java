package com.github.smulyono.samldemo;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;

//import static org.springframework.security.extensions.saml2.config.SAMLConfigurer.saml;

import static com.github.smulyono.samldemo.configurer.SAMLConfigurer.saml;


@EnableWebSecurity
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Value("${security.saml2.metadata-url}")
    String metadataUrl;

    @Value("${server.ssl.key-alias}")
    String keyAlias;

    @Value("${server.ssl.key-store-password}")
    String password;

    @Value("${server.port}")
    String port;

    @Value("${server.ssl.key-store}")
    String keyStoreFilePath;

    @Autowired SimpleSamlUserDetailsService simpleSamlUserDetailsService;
    @Autowired
    ApplicationEventPublisher publisher;

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/saml*","/", "/login*")
                .permitAll()
                .anyRequest().authenticated()
                .and()
            .csrf()
                .csrfTokenRepository(getCsrfTokenRepository())
                .and();


        http
            .formLogin()
                .loginPage("/")
                .loginProcessingUrl("/j_spring_security_check")
                .usernameParameter("username")
                .passwordParameter("password")
                .successHandler(successHandler())
                .failureHandler(failureHandler())
                .permitAll()
            .and()
                .logout()
                .logoutSuccessUrl("/")
            .and()
            .apply(saml())
                .forcePrincipalAsString()
                .userDetailsService(simpleSamlUserDetailsService)
                .successHandler(successHandler())
                .failureHandler(failureHandler())
                .eventPublisher(publisher)
                .serviceProvider()
                    .keyStore()
                    .storeFilePath(this.keyStoreFilePath)
                    .password(this.password)
                    .keyname(this.keyAlias)
                    .keyPassword(this.password)
                    .and()
                .protocol("https")
                .hostname(String.format("%s:%s", "localhost", this.port))
                .basePath("/")
                .and()
            .identityProvider()
                .metadataFilePath(this.metadataUrl)
                .discoveryEnabled(false);

    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("admin")
                .password("admin")
                .roles("ADMIN");
    }

    public CookieCsrfTokenRepository getCsrfTokenRepository() {
        CookieCsrfTokenRepository csrf = new CookieCsrfTokenRepository();
        csrf.setCookieName("test-csrf");
        return csrf;
    }

    @Bean
    public AuthenticationSuccessHandler successHandler() {
        return new customAuthSuccessHandler();
    }

    @Bean
    public AuthenticationFailureHandler failureHandler() {
        return new customAuthFailureHandler();
    }
}

@Slf4j
@Component
class SimpleSamlUserDetailsService implements SAMLUserDetailsService {
    @Value("${security.saml2.user.blocked:''}")
    String blockedUser;


    @Override
    public Object loadUserBySAML(SAMLCredential samlCredential) throws UsernameNotFoundException {
        String username = samlCredential.getNameID().getValue();
        log.info("Testing blocked user {}", blockedUser);
        if (!username.isEmpty() && username.equalsIgnoreCase(blockedUser)) {
            // Will get redirected to 401 error page
            log.info("SHOULD NOT LOGGED IN with {} ", username);
            throw new UsernameNotFoundException("NOT VALID LOGIN!");
        } else {
            log.info("Getting user logged in with {} ", username);
            return new User(username, "dummy", Arrays.asList(new SimpleGrantedAuthority("ADMIN")));
        }
    }
}

@Slf4j
class customAuthSuccessHandler extends
        SavedRequestAwareAuthenticationSuccessHandler implements
        AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {
        log.info("Current authentication logged in user : {} ", authentication.getName());
        response.sendRedirect("/private");
    }
}

@Slf4j
class customAuthFailureHandler extends
        SavedRequestAwareAuthenticationSuccessHandler implements
        AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
        log.info("BAD Authentications!!!");
        httpServletResponse.sendRedirect("/public?error=bad_auth");
    }
}
