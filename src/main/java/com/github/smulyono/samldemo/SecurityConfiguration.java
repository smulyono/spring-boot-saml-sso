package com.github.smulyono.samldemo;

import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.websso.*;

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
                .antMatchers("/saml*","/")
                .permitAll()
                .anyRequest().authenticated()
                .and()
            .logout()
                .logoutUrl("/saml/logout?local=true")
                .logoutSuccessUrl("/")
                .and()
            .apply(saml())
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
            .metadataFilePath(this.metadataUrl);
    }

//    @Bean
//    public SAMLAuthenticationProvider samlAuthenticationProvider() {
//        SAMLAuthenticationProvider newConfig = new SAMLAuthenticationProvider();
//        newConfig.setForcePrincipalAsString(true);
//        return newConfig;
//    }
//    // -- ALL bean dependency which is needed by qualifier type !!! --//
//    // SAML 2.0 Web SSO profile
//    @Bean
//    public WebSSOProfile webSSOprofile() {
//        return new WebSSOProfileImpl();
//    }
//    // SAML 2.0 WebSSO Assertion Consumer
//    @Bean
//    public WebSSOProfileConsumer webSSOprofileConsumer() {
//        return new WebSSOProfileConsumerImpl();
//    }
//    // SAML 2.0 Holder-of-Key WebSSO Assertion Consumer
//    @Bean
//    public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
//        return new WebSSOProfileConsumerHoKImpl();
//    }
//    // SAML 2.0 Holder-of-Key Web SSO profile
//    @Bean
//    public WebSSOProfileConsumerHoKImpl hokWebSSOProfile() {
//        return new WebSSOProfileConsumerHoKImpl();
//    }
//    // Logger for SAML messages and events
//    @Bean
//    public SAMLDefaultLogger samlLogger() {
//        return new SAMLDefaultLogger();
//    }
//    // SAML 2.0 ECP profile
//    @Bean
//    public WebSSOProfileECPImpl ecpprofile() {
//        return new WebSSOProfileECPImpl();
//    }
}


