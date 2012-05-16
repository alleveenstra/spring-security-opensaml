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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.binding.encoding.SAMLMessageEncoder;
import org.opensaml.saml2.binding.encoding.HTTPPostSimpleSignEncoder;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.security.SecurityPolicyResolver;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.security.SecurityException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Required;

public class SAMLMessageHandlerImpl implements SAMLMessageHandler, InitializingBean {

    private static final String SAML_REQUEST_POST_PARAM_NAME = "SAMLRequest";
    private static final String SAML_RESPONSE_POST_PARAM_NAME = "SAMLResponse";

    private VelocityEngine velocityEngine;

    private final SAMLMessageDecoder decoder;
    private SAMLMessageEncoder encoder;
    private final SecurityPolicyResolver resolver;

    private String entityId;

    public SAMLMessageHandlerImpl(SAMLMessageDecoder decoder, SecurityPolicyResolver resolver) {
        super();
        this.decoder = decoder;
        this.resolver = resolver;
    }

    @Required
    public void setVelocityEngine(
            VelocityEngine velocityEngine) {
        this.velocityEngine = velocityEngine;
    }

    public void afterPropertiesSet() throws Exception {
        encoder = new HTTPPostSimpleSignEncoder(velocityEngine, "/templates/saml2-post-simplesign-binding.vm", true);
    }

    @Required
    public void setEntityId(String entityId) {
        this.entityId = entityId;
    }

    public SAMLMessageContext extractSAMLMessageContext(HttpServletRequest request) throws MessageDecodingException, SecurityException {

        BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();

        messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));
        messageContext.setSecurityPolicyResolver(resolver);

        decoder.decode(messageContext);

        return messageContext;

    }

    public void sendSAMLMessage(SignableSAMLObject samlMessage,
                                Endpoint endpoint,
                                HttpServletResponse response) throws MessageEncodingException {

        HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response, false);

        BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();

        messageContext.setOutboundMessageTransport(outTransport);
        messageContext.setPeerEntityEndpoint(endpoint);
        messageContext.setOutboundSAMLMessage(samlMessage);
        messageContext.setOutboundMessageIssuer(entityId);

        encoder.encode(messageContext);

    }

    public String extractSAMLMessage(HttpServletRequest request) {
        if (StringUtils.isNotBlank(request.getParameter(SAML_REQUEST_POST_PARAM_NAME))) {
            return request.getParameter(SAML_REQUEST_POST_PARAM_NAME);
        } else {
            return request.getParameter(SAML_RESPONSE_POST_PARAM_NAME);
        }
    }


}
