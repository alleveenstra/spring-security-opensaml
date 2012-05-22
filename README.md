# Spring Security OpenSAML

**Warning: this is Beta code, do not use it on production systems**

This is an Spring Security module for authentication and authorization with Security Assertion Markup Language.
It uses the [OpenSAML library](http://www.opensaml.org/) from Internet2.

## Step 1 Create a provisioner

When a user logs in, your application can create or update it's existing profile.
Create a class that implements the *nl.surfnet.spring.security.opensaml.Provisioner* interface.
Next, create a bean of the class in your Spring conext.

```xml
<bean id="samlProvisioner" class="org.apache.rave.portal.service.ProvisionerImpl">
  <property name="newAccountService" ref="defaultNewAccountService"/>
  <property name="userService" ref="userService"/>
</bean>
```

## Step 2 Add the certificates of your IDP

```xml
<bean id="samlCertificateStore" class="nl.surfnet.spring.security.opensaml.CertificateStoreImpl">
  <property name="certificates">
    <map>
      <entry key="https://engine.dev.surfconext.nl/authentication/idp/metadata" value="MIID/jCCAuYCCQCs7BsDR2N8tjANBgkqhkiG9w0BAQUFADCBwDELMAkGA1UEBhMCTkwxEDAOBgNVBAgTB1V0cmVjaHQxEDAOBgNVBAcTB1V0cmVjaHQxJTAjBgNVBAoTHFNVUkZuZXQgQlYgLSBUaGUgTmV0aGVybGFuZHMxHzAdBgNVBAsTFkNvbGxhYm9yYXRpb24gU2VydmljZXMxGDAWBgNVBAMTD1NVUkZjb25leHQtdGVzdDErMCkGCSqGSIb3DQEJARYcc3VyZmNvbmV4dC1iZWhlZXJAc3VyZm5ldC5ubDAeFw0xMTA2MjcxNTM0NDFaFw0yMTA2MjQxNTM0NDFaMIHAMQswCQYDVQQGEwJOTDEQMA4GA1UECBMHVXRyZWNodDEQMA4GA1UEBxMHVXRyZWNodDElMCMGA1UEChMcU1VSRm5ldCBCViAtIFRoZSBOZXRoZXJsYW5kczEfMB0GA1UECxMWQ29sbGFib3JhdGlvbiBTZXJ2aWNlczEYMBYGA1UEAxMPU1VSRmNvbmV4dC10ZXN0MSswKQYJKoZIhvcNAQkBFhxzdXJmY29uZXh0LWJlaGVlckBzdXJmbmV0Lm5sMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA27T+ALNpoU9PAvRYj2orOXaEVcy1fHSU/rZEakpgNzOFIEL9UB6BvtWdRbO5FT84yN+x2Qzpu6WLpwU7JFb36aRwPmBmabxUx95DhNQNFGA3ZkHu6DOA81GiG0Ll9p9S/EV2fmHGJdJjh5BP1v0/y7bJ/2JmvdzH+cFhEhFk0Ex9HNbC0Hmy9Sn8EXbg3RQO5/2e51wSv4uGALkyGM6lrOG/R1GenoAI8Ys7LNxj3NGkhKRUtpwHoIViWU5cOy26kG9VOG9bAVk51l0LNayMqyieX9UrCp1akQuP3Ir/ogtbKo2zg63Ho1cc43tHHdLZTHp2TWRRGEgnskvGZLddzwIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQB8eUq/0ArBGnPZHNn2o2ip+3i0U4r0swKXjuYL/o2VXqo3eI9j/bCvWw5NOLQVbk/Whc6dSeYIt1oVW/ND4iQZ7LHZr9814IOE3KLGIMeZgjPsXH15o9W4aLC0npPYilw96dfIAq49tOn44jhsRHrdR8z/NFPXE09ehAEb7fOIrxdlf7YDGYx+gXLEnsJo75E6LwCr/y/MBd13DDJNc1HUViiEz+Mkfo4FEKe/5HgEvDy2XjuE1juDCqJ/07pBPHBd0DtM7uaxGw+Zt/Fc4uE0NvtlCZqShFUvMmqHL5oENOlfTmBSWJMbBAGs2O/JQirG2aYcULqXYoCGIPUF49Z6"/>
      <entry key="https://mujina-idp.dev.surfconext.nl/" value="MIICHzCCAYgCCQD7KMJ17XQa7TANBgkqhkiG9w0BAQUFADBUMQswCQYDVQQGEwJOTDEQMA4GA1UECAwHVXRyZWNodDEQMA4GA1UEBwwHVXRyZWNodDEQMA4GA1UECgwHU3VyZm5ldDEPMA0GA1UECwwGQ29uZXh0MB4XDTEyMDMwODA4NTQyNFoXDTEzMDMwODA4NTQyNFowVDELMAkGA1UEBhMCTkwxEDAOBgNVBAgMB1V0cmVjaHQxEDAOBgNVBAcMB1V0cmVjaHQxEDAOBgNVBAoMB1N1cmZuZXQxDzANBgNVBAsMBkNvbmV4dDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA2slVe459WUDL4RXxJf5h5t5oUbPkPlFZ9lQysSoS3fnFTdCgzA6FzQzGRDcfRj0HnWBdA1YH+LxBjNcBIJ/nBc7Ssu4e4rMO3MSAV5Ouo3MaGgHqVq6dCD47f52b98df6QTAA3C+7sHqOdiQ0UDCAK0C+qP5LtTcmB8QrJhKmV8CAwEAATANBgkqhkiG9w0BAQUFAAOBgQCvPhO0aSbqX7g7IkR79IFVdJ/P7uSlYFtJ9cMxec85cYLmWL1aVgF5ZFFJqC25blyPJu2GRcSxoVwB3ae8sPCECWwqRQA4AHKIjiW5NgrAGYR++ssTOQR8mcAucEBfNaNdlJoy8GdZIhHZNkGlyHfY8kWS3OWkGzhWSsuRCLl78A=="/>
    </map>
  </property>
</bean>
```

## Step 3 Create a service provider

```xml
<opensaml:service-provider id="samlAuthenticationProvider"
                         message-handler-ref="samlMessageHandler"
                         preauth-filter-ref="samlPreAuthFilter"
                         entity-id="${ISSUING_ENTITY_ID}"
                         assertion-consumer-uri="${ASSERTION_CONSUMER_URI}"
                         provisioner-ref="samlProvisioner"
                         certificatestore-ref="samlCertificateStore"
                         authentication-manager-ref="authenticationManager" />
```

## Step 4 Add security filter chain configuration

Within `&lt;security:http&gt;` add the following configuration

```xml
<security:custom-filter position="PRE_AUTH_FILTER" ref="samlPreAuthFilter" />
<security:intercept-url pattern="/OpenSAML.sso/Login" access="permitAll"/>
<security:intercept-url pattern="${ASSERTION_CONSUMER_URI}"
                         access="hasAnyRole(ROLE_ANONYMOUS,ROLE_ADMIN,ROLE_USER)"/>
```

## Step 5 Set the authentication provider

```xml
<security:authentication-manager alias="authenticationManager">
  <security:authentication-provider ref="samlAuthenticationProvider"/>
</security:authentication-manager>
```

## Step 6 Add an AuthN request controller

```xml
<bean id="authnRequestController" class="nl.surfnet.spring.security.opensaml.controller.AuthnRequestController">
  <property name="SAMLMessageHandler" ref="samlMessageHandler" />
  <property name="assertionConsumerServiceURL" value="${ASSERTION_CONSUMER_URL}" />
  <property name="entityID" value="${ISSUING_ENTITY_ID}"/>
</bean>
```

## Step 7 Create either a redirect or a WAYF page

When your application requires a user is logged in you can redirect it to the AuthN request controller.

For a single identity provider add the following rule in the security filter chain:

```xml
<security:form-login login-page="/OpenSAML.sso/Login?target=https://engine.dev.surfconext.nl/authentication/idp/single-sign-on" default-target-url="/" />
```

When you connect with multiple identity providers, you can show a *Where Are You From* (WAYF) page.

```xml
<security:intercept-url pattern="/myloginpage.jsp" access="permitAll"/>
<security:form-login login-page="/myloginpage.jsp" default-target-url="/" />
```

Example of myloginpage.jsp:

```html
<a href="OpenSAML.sso/Login?target=https://engine.dev.surfconext.nl/authentication/idp/single-sign-on">
    Login at surfconext
</a>

<a href="OpenSAML.sso/Login?target=https://openidp.feide.no/simplesaml/saml2/idp/SSOService.php">
    Login at feido.no
</a>

<a href="OpenSAML.sso/Login?target=https://mujina-idp.dev.surfconext.nl/SingleSignOnService">
    Login at Mujina
</a>
```


