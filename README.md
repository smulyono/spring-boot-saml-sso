How to run : 

* Create `application-secret.yaml` under src/main/resources
```
security:
  saml2:
    metadata-url: [okta saml url]
```

* Run main application `com.github.smulyono.samldemo.SsoOktaApplication` 

OR

* $ mvn spring-boot:run

