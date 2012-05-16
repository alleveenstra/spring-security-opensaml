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

import org.opensaml.Configuration;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.security.SecurityPolicyException;
import org.opensaml.ws.security.SecurityPolicyRule;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.CredentialResolver;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Required;

/**
 * Rule to check that the message has been signed by an issuer that has credentials
 * in the keystore.
 * <p/>
 * We could use a SAMLProtocolMessageXMLSignatureSecurityPolicyRule, but, that
 * relies on role info to be set (which we will not be using).  Also, we will insist
 * that the message be signed and not rely on an additional rule to check the isAuthenticated
 * flag on the message context.
 */
public class SignatureSecurityPolicyRule implements InitializingBean, SecurityPolicyRule {

    private final static Logger log = LoggerFactory.getLogger(SignatureSecurityPolicyRule.class);

    private CredentialResolver credentialResolver;
    private final SAMLSignatureProfileValidator samlSignatureProfileValidator;
    ExplicitKeySignatureTrustEngine trustEngine;

    public SignatureSecurityPolicyRule(SAMLSignatureProfileValidator samlSignatureProfileValidator) {
        super();
        this.samlSignatureProfileValidator = samlSignatureProfileValidator;
    }

    @Required
    public void setCredentialResolver(final CredentialResolver credentialResolver) {
        this.credentialResolver = credentialResolver;
    }

    public void afterPropertiesSet() throws Exception {

        System.out.println("Aap " + Configuration.getGlobalSecurityConfiguration());

        KeyInfoCredentialResolver keyInfoCredResolver =
                Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver();

        trustEngine = new ExplicitKeySignatureTrustEngine(credentialResolver, keyInfoCredResolver);
    }

    public void evaluate(MessageContext messageContext) throws SecurityPolicyException {

        log.debug("evaluating signature of {}", messageContext);

        if (!(messageContext.getInboundMessage() instanceof SignableSAMLObject)) {
            throw new SecurityPolicyException("Inbound Message is not a SignableSAMLObject");
        }

        Response response = (Response) messageContext.getInboundMessage();

        Assertion assertion = response.getAssertions().get(0);

        if (!response.isSigned() && !assertion.isSigned()) {
            throw new SecurityPolicyException("The SAML response was not signed");
        }

        // Verify the response signature
        if (response.isSigned()) {
            checkSignatureProfile(response);
            checkMessageSignature(messageContext, response);
        }

        // Verify the assertion signature
        if (assertion.isSigned()) {
            checkSignatureProfile(assertion);
            checkMessageSignature(messageContext, assertion);
        }
    }

    private void checkSignatureProfile(SignableSAMLObject samlMessage)
            throws SecurityPolicyException {
        try {
            final Signature signature = samlMessage.getSignature();
            if (signature != null) {
                samlSignatureProfileValidator.validate(signature);
            }
        } catch (ValidationException ve) {

            throw new SecurityPolicyException("Signature did not conform to SAML Signature profile", ve);
        }
    }

    private void checkMessageSignature(MessageContext messageContext,
                                       SignableSAMLObject samlMessage) throws SecurityPolicyException {
        CriteriaSet criteriaSet = new CriteriaSet();
        log.debug("Inbound issuer is {}", messageContext.getInboundMessageIssuer());
        criteriaSet.add( new EntityIDCriteria(messageContext.getInboundMessageIssuer()));
        criteriaSet.add( new UsageCriteria(UsageType.SIGNING) );

        try {
            if (!trustEngine.validate( samlMessage.getSignature(), criteriaSet)) {
                throw new SecurityPolicyException("Signature was either invalid or signing key could not be established as trusted");
            }
        } catch (org.opensaml.xml.security.SecurityException e) {
            throw new SecurityPolicyException("Error evaluating the signature", e);
        }
    }
}
