/*
 * Copyright 2012 SURFnet bv, The Netherlands
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package nl.surfnet.spring.security.opensaml;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Required;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.userdetails.UserDetails;

import nl.surfnet.spring.security.opensaml.xml.SAML2ValidatorSuite;

public class AssertionConsumerImpl implements AssertionConsumer {

    private final static Logger log = LoggerFactory
            .getLogger(AssertionConsumerImpl.class);

    private Provisioner provisioner;

    @Required
    public void setProvisioner(final Provisioner provisioner) {
        this.provisioner = provisioner;
    }

    SAML2ValidatorSuite validatorSuite = new SAML2ValidatorSuite();

    public UserDetails consume(Response samlResponse) throws AuthenticationException {


        try {
            validatorSuite.validate(samlResponse);
        } catch (ValidationException ve) {
            log.warn("Response Message failed Validation", ve);
            throw new ServiceProviderAuthenticationException("Invalid SAML REsponse Message", ve);
        }

        checkResponseStatus(samlResponse);

        Assertion assertion = samlResponse.getAssertions().get(0);

        log.debug("authenticationResponseIssuingEntityName {}", samlResponse.getIssuer().getValue());

        log.debug("assertion.getID() {}", assertion.getID());
        log.debug("assertion.getSubject().getNameID().getValue() {}", assertion.getSubject().getNameID().getValue());

        AuthnStatement authnStatement = assertion.getAuthnStatements().get(0);

        log.debug("authnStatement.getAuthnInstant() {}", authnStatement.getAuthnInstant());

        Set<GrantedAuthority> authorities = extractAuthorities(assertion.getAttributeStatements());
        log.debug("Granted Authorities will be {}", authorities);

        log.debug("assertion.getID() {}", assertion.getAuthnStatements());

        return provisioner.provisionUser(assertion);

    }

    private Set<GrantedAuthority> extractAuthorities(
            List<AttributeStatement> attributeStatements) {

        Set<GrantedAuthority> authorities = new HashSet<GrantedAuthority>();
        for (AttributeStatement attributeStatement : attributeStatements) {
            for (Attribute attribute : attributeStatement.getAttributes()) {
                if (GrantedAuthority.class.getName().equalsIgnoreCase(attribute.getName())) {
                    log.debug("found Granted Authorities.");
                    for (XMLObject xmlObj : attribute.getAttributeValues()) {
                        if (xmlObj instanceof XSString)
                            authorities.add(new GrantedAuthorityImpl(((XSString) xmlObj).getValue()));
                    }
                    return authorities;
                }
            }
        }
        // return default
        authorities.add(new GrantedAuthorityImpl("ROLE_USER"));
        return authorities;
    }

    private void checkResponseStatus(Response samlResponse) {


        if (StatusCode.SUCCESS_URI.equals(StringUtils.trim(samlResponse.getStatus().getStatusCode().getValue()))) {

            additionalValidationChecksOnSuccessfulResponse(samlResponse);

        } else {

            StringBuilder extraInformation = extractExtraInformation(samlResponse);

            if (extraInformation.length() > 0) {
                log.warn("Extra information extracted from authentication failure was {}", extraInformation.toString());

                throw new IdentityProviderAuthenticationException("Identity Provider has failed the authentication.", extraInformation.toString());
            } else {
                throw new IdentityProviderAuthenticationException("Identity Provider has failed the authentication.");
            }

        }
    }

    private void additionalValidationChecksOnSuccessfulResponse(
            Response samlResponse) {
        //saml validator suite does not check for assertions on successful auths
        if (samlResponse.getAssertions().isEmpty()) {
            throw new ServiceProviderAuthenticationException("Successful Response did not contain any assertions");
        }

        //nor authnStatements
        else if (samlResponse.getAssertions().get(0).getAuthnStatements().isEmpty()) {
            throw new ServiceProviderAuthenticationException("Successful Response did not contain an assertions with an AuthnStatement");
        }

        //we require at attribute statements
        else if (samlResponse.getAssertions().get(0).getAttributeStatements().isEmpty()) {
            throw new ServiceProviderAuthenticationException("Successful Response did not contain an assertions with an AttributeStatements");

        }
        //we will require an issuer
        else if (samlResponse.getIssuer() == null) {
            throw new ServiceProviderAuthenticationException("Successful Response did not contain any Issuer");

        }
    }

    private StringBuilder extractExtraInformation(Response samlResponse) {
        StringBuilder extraInformation = new StringBuilder();

        if (samlResponse.getStatus().getStatusCode().getStatusCode() != null) {

            extraInformation.append(samlResponse.getStatus().getStatusCode().getStatusCode().getValue());
        }

        if (samlResponse.getStatus().getStatusMessage() != null) {
            if (extraInformation.length() > 0) {
                extraInformation.append("  -  ");
            }
            extraInformation.append(samlResponse.getStatus().getStatusMessage());
        }
        return extraInformation;
    }

}
