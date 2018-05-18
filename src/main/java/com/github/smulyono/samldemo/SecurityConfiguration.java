package com.github.smulyono.samldemo;

import lombok.extern.log4j.Log4j;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.PriorityOrdered;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.stereotype.Service;

import javax.servlet.Filter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.springframework.security.extensions.saml2.config.SAMLConfigurer.saml;

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
                .successHandler(new customAuthSuccessHandler())
                .permitAll()
            .and()
                .logout()
                .logoutSuccessUrl("/")
            .and()
            .apply(saml())
                .forcePrincipalAsString()
                .userDetailsService(new SimpleSamlUserDetailsService())
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
}

@Slf4j
class SimpleSamlUserDetailsService implements SAMLUserDetailsService {

    @Override
    public Object loadUserBySAML(SAMLCredential samlCredential) throws UsernameNotFoundException {
        String username = samlCredential.getNameID().getValue();
        if (username.equalsIgnoreCase("smulyono+1@ciphercloud.com")) {
            log.info("Getting user logged in with {} ", username);
            return new User(username, "dummy", Arrays.asList(new SimpleGrantedAuthority("ADMIN")));
        } else {
            // Will get redirected to 401 error page
            log.info("SHOULD NOT LOGGED IN with {} ", username);
            throw new UsernameNotFoundException("NOT VALID LOGIN!");
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
@Service
class DefaultRolesPrefixPostProcessor implements BeanPostProcessor, PriorityOrdered {

    @Override
    public Object postProcessBeforeInitialization(Object o, String s) throws BeansException {
        return o;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        if (bean instanceof FilterChainProxy) {

            FilterChainProxy chains = (FilterChainProxy) bean;

            for (SecurityFilterChain chain : chains.getFilterChains()) {
                for (Filter filter : chain.getFilters()) {
                    log.info("Filter registered {}", filter.getClass().toGenericString());
                }
            }
        }
        return bean;
    }

    @Override
    public int getOrder() {
        return 0;
    }
}

