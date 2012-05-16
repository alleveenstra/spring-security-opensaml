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

package nl.surfnet.spring.security.opensaml.config;

import java.io.IOException;
import java.util.Properties;

import org.apache.commons.lang.StringUtils;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.binding.security.IssueInstantRule;
import org.opensaml.common.binding.security.MessageReplayRule;
import org.opensaml.saml2.binding.decoding.HTTPPostSimpleSignDecoder;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.util.storage.MapBasedStorageService;
import org.opensaml.util.storage.ReplayCache;
import org.opensaml.ws.security.provider.StaticSecurityPolicyResolver;
import org.opensaml.xml.parse.BasicParserPool;
import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.ui.velocity.VelocityEngineFactoryBean;
import org.w3c.dom.Element;

import nl.surfnet.spring.security.opensaml.AssertionConsumerImpl;
import nl.surfnet.spring.security.opensaml.AuthenticationFailureHandlerImpl;
import nl.surfnet.spring.security.opensaml.SAMLMessageHandlerImpl;
import nl.surfnet.spring.security.opensaml.SAMLResponseAuthenticationProcessingFilter;
import nl.surfnet.spring.security.opensaml.SAMLResponseAuthenticationProvider;
import nl.surfnet.spring.security.opensaml.SecurityPolicyDelegate;
import nl.surfnet.spring.security.opensaml.SignatureSecurityPolicyRule;
import nl.surfnet.spring.security.opensaml.crypt.KeyStoreCredentialResolverDelegate;

public class ServiceProviderBeanDefinitionParser extends AbstractBeanDefinitionParser {

    public static final String BEAN_REPLAYCACHE = "samlReplayCache";
    public static final String BEAN_KEYSTORECREDENTIALRESOLVER = "samlKeyStoreCredentialResolverDelegate";
    public static final String BEAN_SECURITYPOLICY = "samlSecurityPolicy";
    public static final String BEAN_SECURITYPOLICYRESOLVER = "samlSecurityPolicyResolver";
    public static final String BEAN_SAMLINITIALIZER = "samlInitializer";
    public static final String BEAN_ASSERTIONCONSUMER = "samlAssertionConsumer";
    public static final String BEAN_AUTHENTICATIONPROVIDER = "samlAuthenticationProvider";

    private int newClockSkew = 90;
    private int newExpires = 300;
    private long replayCacheDuration = 14400000;
    private int poolSizeInt = 2;

    @Override
    protected AbstractBeanDefinition parseInternal(final Element element, final ParserContext parserContext) {

        final String preAuthFilterRef = element.getAttribute("preauth-filter-ref");
        if (StringUtils.isBlank(preAuthFilterRef)) {
            parserContext.getReaderContext().error("The preauth-filter-ref is mandatory", element);
        }

        final String messageHandlerRef = element.getAttribute("message-handler-ref");
        if (StringUtils.isBlank(messageHandlerRef)) {
            parserContext.getReaderContext().error("The message-handler-ref is mandatory", element);
        }

        final String certificatestoreRef = element.getAttribute("certificatestore-ref");
        if (StringUtils.isBlank(certificatestoreRef)) {
            parserContext.getReaderContext().error("The certificatestore-ref is mandatory", element);
        }

        final String provisionerRef = element.getAttribute("provisioner-ref");
        if (StringUtils.isBlank(provisionerRef)) {
            parserContext.getReaderContext().error("The provisioner-ref is mandatory", element);
        }

        final String authenticationManangerRef = element.getAttribute("authentication-manager-ref");
        if (StringUtils.isBlank(authenticationManangerRef)) {
            parserContext.getReaderContext().error("The authentication-manager-ref is mandatory", element);
        }

        final String entityID = element.getAttribute("entity-id");
        if (StringUtils.isBlank(entityID)) {
            parserContext.getReaderContext().error("The entity-id is mandatory", element);
        }

        final String assertionConsumerURI = element.getAttribute("assertion-consumer-uri");
        if (StringUtils.isBlank(assertionConsumerURI)) {
            parserContext.getReaderContext().error("Missing or empty assertion-consumer-uri.", element);
        }

        final String poolSize = element.getAttribute("max-parser-pool-size");
        try {
            poolSizeInt = Integer.parseInt(poolSize);
        } catch(NumberFormatException nfe) {
            parserContext.getReaderContext().error("An invalid value for max-parser-pool-size was supplied", element);
        }

        final String replayCacheLife = element.getAttribute("replay-cache-life-in-millis");
        try {
            replayCacheDuration = Integer.parseInt(replayCacheLife);
        } catch(NumberFormatException nfe) {
            parserContext.getReaderContext().error("An invalid value for replay-cache-life-in-millis was supplied", element);
        }

        final String clockSkew = element.getAttribute("issue-instant-check-clock-skew-in-secs");
        try {
            newClockSkew = Integer.parseInt(clockSkew);
        } catch(NumberFormatException nfe) {
            parserContext.getReaderContext().error("An invalid value for issue-instant-check-clock-skew-in-secs was supplied", element);
        }

        final String validTime = element.getAttribute("issue-instant-check-valid-time-in-secs");
        try {
            newExpires = Integer.parseInt(validTime);
        } catch(NumberFormatException nfe) {
            parserContext.getReaderContext().error("An invalid value for issue-instant-check-valid-time-in-secs was supplied", element);
        }

        BeanDefinitionBuilder bootstrapBean = BeanDefinitionBuilder.genericBeanDefinition(DefaultBootstrap.class);
        bootstrapBean.setInitMethodName("bootstrap");
        parserContext.getRegistry().registerBeanDefinition(BEAN_SAMLINITIALIZER, bootstrapBean.getBeanDefinition());

        final BasicParserPool basicParserPool = new BasicParserPool();
        basicParserPool.setMaxPoolSize(poolSizeInt);

        final HTTPPostSimpleSignDecoder httpPostSimpleSignDecoder = new HTTPPostSimpleSignDecoder(basicParserPool);

        final VelocityEngineFactoryBean velocityEngineFactoryBean = new VelocityEngineFactoryBean();
        velocityEngineFactoryBean.setPreferFileSystemAccess(false);
        Properties velocityEngineProperties = new Properties();
        velocityEngineProperties.setProperty("resource.loader", "classpath");
        velocityEngineProperties.setProperty("classpath.resource.loader.class", "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
        velocityEngineFactoryBean.setVelocityProperties(velocityEngineProperties);
        VelocityEngine velocityEngine = null;
        try {
            velocityEngine = velocityEngineFactoryBean.createVelocityEngine();
        } catch (IOException e) {
            throw new RuntimeException("Unable to create velocity engine instance");
        }

        // Replay cache
        BeanDefinitionBuilder replayCacheBuilder = BeanDefinitionBuilder.genericBeanDefinition(ReplayCache.class);
        replayCacheBuilder.addConstructorArgValue(new MapBasedStorageService());
        replayCacheBuilder.addConstructorArgValue(replayCacheDuration);
        parserContext.getRegistry().registerBeanDefinition(BEAN_REPLAYCACHE, replayCacheBuilder.getBeanDefinition());

        // Message replay rule
        BeanDefinitionBuilder messageReplayRuleBuilder = BeanDefinitionBuilder.genericBeanDefinition(MessageReplayRule.class);
        messageReplayRuleBuilder.addConstructorArgReference(BEAN_REPLAYCACHE);
        parserContext.getRegistry().registerBeanDefinition("messageReplayRule", messageReplayRuleBuilder.getBeanDefinition());

        // Issue instant rule
        BeanDefinitionBuilder issueInstantBuilder = BeanDefinitionBuilder.genericBeanDefinition(IssueInstantRule.class);
        issueInstantBuilder.addConstructorArgValue(newClockSkew);
        issueInstantBuilder.addConstructorArgValue(newExpires);
        parserContext.getRegistry().registerBeanDefinition("issueInstantRule", issueInstantBuilder.getBeanDefinition());

        // KeyStore Credential Resolver
        BeanDefinitionBuilder keyStoreBuilder = BeanDefinitionBuilder.genericBeanDefinition(KeyStoreCredentialResolverDelegate.class);
        keyStoreBuilder.addPropertyReference("certificateStore", certificatestoreRef);
        parserContext.getRegistry().registerBeanDefinition(BEAN_KEYSTORECREDENTIALRESOLVER, keyStoreBuilder.getBeanDefinition());

        // Signature Rule Builder
        BeanDefinitionBuilder signatureRuleBuilder = BeanDefinitionBuilder.genericBeanDefinition(SignatureSecurityPolicyRule.class);
        signatureRuleBuilder.addConstructorArgValue(new SAMLSignatureProfileValidator());
        signatureRuleBuilder.addPropertyReference("credentialResolver", BEAN_KEYSTORECREDENTIALRESOLVER);

        // List of rule beans
        final ManagedList<BeanMetadataElement> beanMetadataElements = new ManagedList<BeanMetadataElement>();
        beanMetadataElements.add(signatureRuleBuilder.getBeanDefinition());
        beanMetadataElements.add(issueInstantBuilder.getBeanDefinition());
        beanMetadataElements.add(messageReplayRuleBuilder.getBeanDefinition());

        // Security Policy
        BeanDefinitionBuilder securityPolicyDelegateBuilder = BeanDefinitionBuilder.genericBeanDefinition(SecurityPolicyDelegate.class);
        securityPolicyDelegateBuilder.addConstructorArgValue(beanMetadataElements);
        parserContext.getRegistry().registerBeanDefinition(BEAN_SECURITYPOLICY, securityPolicyDelegateBuilder.getBeanDefinition());

        // Security Policy Resolver
        BeanDefinitionBuilder securityPolicyResolverBuilder = BeanDefinitionBuilder.genericBeanDefinition(StaticSecurityPolicyResolver.class);
        securityPolicyResolverBuilder.addConstructorArgReference(BEAN_SECURITYPOLICY);
        parserContext.getRegistry().registerBeanDefinition(BEAN_SECURITYPOLICYRESOLVER, securityPolicyResolverBuilder.getBeanDefinition());

        // Message Handler
        BeanDefinitionBuilder postBindingAdapter = BeanDefinitionBuilder
                .rootBeanDefinition(SAMLMessageHandlerImpl.class);
        postBindingAdapter.addConstructorArgValue(httpPostSimpleSignDecoder);
        postBindingAdapter.addConstructorArgReference(BEAN_SECURITYPOLICYRESOLVER);
        postBindingAdapter.addPropertyValue("velocityEngine", velocityEngine);
        postBindingAdapter.addPropertyValue("entityId", entityID);
        parserContext.getRegistry().registerBeanDefinition(messageHandlerRef, postBindingAdapter.getBeanDefinition());

        // Assertion Consumer Bean
        BeanDefinitionBuilder assertionComsumerBean = BeanDefinitionBuilder.genericBeanDefinition(AssertionConsumerImpl.class);
        assertionComsumerBean.addPropertyReference("provisioner", provisionerRef);
        parserContext.getRegistry().registerBeanDefinition(BEAN_ASSERTIONCONSUMER, assertionComsumerBean.getBeanDefinition());

        BeanDefinitionBuilder authenticationProvider = BeanDefinitionBuilder
                .rootBeanDefinition(SAMLResponseAuthenticationProvider.class);
        authenticationProvider.addConstructorArgReference(BEAN_ASSERTIONCONSUMER);
        parserContext.getRegistry().registerBeanDefinition(BEAN_AUTHENTICATIONPROVIDER, authenticationProvider.getBeanDefinition());

        // Pre Auth Filter
        final HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
        final AuthenticationFailureHandlerImpl authenticationFailureHandler = new AuthenticationFailureHandlerImpl(requestCache);

        // Authentication Filter
        BeanDefinitionBuilder authenticationFilter = BeanDefinitionBuilder
                .rootBeanDefinition(SAMLResponseAuthenticationProcessingFilter.class);
        authenticationFilter.addConstructorArgValue(assertionConsumerURI);
        authenticationFilter.addPropertyReference("SAMLMessageHandler", messageHandlerRef);
        authenticationFilter.addPropertyReference("authenticationManager", authenticationManangerRef);
        authenticationFilter.addPropertyValue("authenticationFailureHandler", authenticationFailureHandler);
        parserContext.getRegistry().registerBeanDefinition(preAuthFilterRef, authenticationFilter.getBeanDefinition());

        return authenticationProvider.getBeanDefinition();
    }
}
