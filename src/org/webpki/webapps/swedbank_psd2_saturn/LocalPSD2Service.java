/*
 *  Copyright 2006-2019 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.webapps.swedbank_psd2_saturn;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.util.LinkedHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.KeyStoreVerifier;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;
import org.webpki.util.PEMDecoder;
import org.webpki.saturn.common.KeyStoreEnumerator;
import org.webpki.webutil.InitPropertyReader;

public class LocalPSD2Service extends InitPropertyReader implements ServletContextListener {

    static Logger logger = Logger.getLogger(LocalPSD2Service.class.getName());

    static KeyStoreVerifier certificateVerifier;

    static boolean logging;

    static String oauth2ClientId;
    
    static String oauth2ClientSecret;

    static String oauth2RedirectUri;

    static final String OAUTH2_CLIENT_ID        = "oauth2_client_id";
    
    static final String OAUTH2_CLIENT_SECRET    = "oauth2_client_secret";

    static final String OAUTH2_REDIRECT_URI     = "oauth2_redirect_uri";

    InputStream getResource(String name) throws IOException {
        InputStream is = this.getClass().getResourceAsStream(name);
        if (is == null) {
            throw new IOException("Resource fail for: " + name);
        }
        return is;
    }
 
    byte[] getEmbeddedResourceBinary(String name) throws IOException {
        return ArrayUtil.getByteArrayFromInputStream(getResource(name));
    }

    String getEmbeddedResourceString(String name) throws IOException {
        return new String(getEmbeddedResourceBinary(name), "utf-8");
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
    }

    @Override
    public void contextInitialized(ServletContextEvent event) {
        initProperties(event);
        try {
            oauth2ClientId = getPropertyString(OAUTH2_CLIENT_ID);
            oauth2ClientSecret = getPropertyString(OAUTH2_CLIENT_SECRET);
            oauth2RedirectUri = getPropertyString(OAUTH2_REDIRECT_URI);
    //        new KeyStoreEnumerator(null,null);
/*
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            keyStore.setCertificateEntry(
                          "mykey",
                          PEMDecoder.getRootCertificate(getEmbeddedResourceBinary("rootca.pem")));
            certificateVerifier = new KeyStoreVerifier(keyStore);
*/
            
            /////////////////////////////////////////////////////////////////////////////////////////////
            // Logging?
            /////////////////////////////////////////////////////////////////////////////////////////////
            logging = getPropertyBoolean("logging");

            logger.info("Swedbank PSD2 Demo Successfully Initiated");
        } catch (Exception e) {
            logger.log(Level.SEVERE, "********\n" + e.getMessage() + "\n********", e);
        }
    }
}
