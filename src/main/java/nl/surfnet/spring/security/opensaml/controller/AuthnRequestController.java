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

package nl.surfnet.spring.security.opensaml.controller;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Required;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import nl.surfnet.spring.security.opensaml.AuthnRequestGenerator;
import nl.surfnet.spring.security.opensaml.SAMLMessageHandler;
import nl.surfnet.spring.security.opensaml.util.IDService;
import nl.surfnet.spring.security.opensaml.util.TimeService;
import nl.surfnet.spring.security.opensaml.xml.EndpointGenerator;

@Controller
public class AuthnRequestController {
    private final static Logger log = LoggerFactory.getLogger(AuthnRequestController.class);

    private final TimeService timeService;
    private final IDService idService;

    private SAMLMessageHandler samlMessageHandler;

    private String assertionConsumerServiceURL;

    private String entityID;

    public AuthnRequestController() {
        this.timeService = new TimeService();
        this.idService = new IDService();
    }

    @Required
    public void setSAMLMessageHandler(SAMLMessageHandler samlMessageHandler) {
        this.samlMessageHandler = samlMessageHandler;
    }

    @Required
    public void setAssertionConsumerServiceURL(String assertionConsumerServiceURL) {
        this.assertionConsumerServiceURL = assertionConsumerServiceURL;
    }

    @Required
    public void setEntityID(final String entityID) {
        this.entityID = entityID;
    }

    @RequestMapping(value = {"/OpenSAML.sso/Login"}, method = RequestMethod.GET)
    public void commence(
            @RequestParam(value="target") String target,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        AuthnRequestGenerator authnRequestGenerator = new AuthnRequestGenerator(entityID, timeService, idService);
        EndpointGenerator endpointGenerator = new EndpointGenerator();

        Endpoint endpoint = endpointGenerator.generateEndpoint(SingleSignOnService.DEFAULT_ELEMENT_NAME, target, assertionConsumerServiceURL);

        AuthnRequest authnReqeust = authnRequestGenerator.generateAuthnRequest(target, assertionConsumerServiceURL);

        log.debug("Sending authnRequest to {}", target);

        try {
            CriteriaSet criteriaSet = new CriteriaSet();
            criteriaSet.add(new EntityIDCriteria(entityID));
            criteriaSet.add(new UsageCriteria(UsageType.SIGNING));

            samlMessageHandler.sendSAMLMessage(authnReqeust, endpoint, response);
        } catch (MessageEncodingException mee) {
            log.error("Could not send authnRequest to Identity Provider.", mee);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }
}
