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

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Map;

import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Required;

public class CertificateStoreImpl implements CertificateStore, InitializingBean {
    private String keystorePassword;
    private KeyStore keyStore;
    private Map<String, String> certificates;

    @Required
    public void setCertificates(Map<String, String> certificates) {
        this.certificates = certificates;
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }

    public void afterPropertiesSet() throws Exception {
        keystorePassword = "secret";
        try {
            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, keystorePassword.toCharArray());
            for (Map.Entry<String, String> entry : certificates.entrySet()) {
                appendToKeyStore(entry.getKey(), entry.getValue());
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void appendToKeyStore(String keyAlias, String pemCert) throws Exception {
        String wrappedCert = "-----BEGIN CERTIFICATE-----\n" + pemCert + "\n-----END CERTIFICATE-----";
        ByteArrayInputStream certificateInputStream = new ByteArrayInputStream(wrappedCert.getBytes());
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        final Certificate cert = certificateFactory.generateCertificate(certificateInputStream);
        IOUtils.closeQuietly(certificateInputStream);
        keyStore.setCertificateEntry(keyAlias, cert);
    }
}
