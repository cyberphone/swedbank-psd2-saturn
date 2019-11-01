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
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;

import java.security.cert.X509Certificate;

import java.security.interfaces.RSAKey;

import java.security.spec.ECGenParameterSpec;

import java.util.Vector;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.Context;
import javax.naming.InitialContext;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import javax.sql.DataSource;

import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.KeyStoreVerifier;

import org.webpki.json.DataEncryptionAlgorithms;
import org.webpki.json.JSONDecoderCache;
import org.webpki.json.JSONDecryptionDecoder;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONParser;
import org.webpki.json.JSONX509Verifier;
import org.webpki.json.KeyEncryptionAlgorithms;

import org.webpki.keygen2.CredentialDiscoveryResponseDecoder;
import org.webpki.keygen2.InvocationResponseDecoder;
import org.webpki.keygen2.KeyCreationResponseDecoder;
import org.webpki.keygen2.ProvisioningFinalizationResponseDecoder;
import org.webpki.keygen2.ProvisioningInitializationResponseDecoder;

import org.webpki.util.ArrayUtil;

import org.webpki.saturn.common.AuthorityObjectManager;
import org.webpki.saturn.common.ExternalCalls;
import org.webpki.saturn.common.KeyStoreEnumerator;
import org.webpki.saturn.common.PaymentMethods;
import org.webpki.saturn.common.ProviderAuthority;
import org.webpki.saturn.common.ServerX509Signer;
import org.webpki.saturn.common.SignatureProfiles;

import org.webpki.webutil.InitPropertyReader;

import org.webpki.webapps.swedbank_psd2_saturn.api.OpenBanking;

// This is the starting point for LIS (Local Integration Service)

public class LocalIntegrationService extends InitPropertyReader implements ServletContextListener {

    static Logger logger = Logger.getLogger(LocalIntegrationService.class.getName());

    static KeyStoreVerifier certificateVerifier;

    public static boolean logging;
    
    static final String LOGGING                     = "logging";

    static final String KEYSTORE_PASSWORD           = "key_password";
   
    static final String TEST_MERCHANT_URL           = "test_merchant_url";

    public static String testMerchantUrl;

    /////////////////////////////////////////////////////////////////////////////
    // Bank objects
    /////////////////////////////////////////////////////////////////////////////
    public static String bankBaseUrl;

    static final String BANK_BASE_URL               = "bank_base_url";

    static final String BANK_COMMON_NAME            = "bank_common_name";

    static final String BANK_EECERT                 = "bank_eecert";
    
    static final String BANK_ENCRYPT                = "bank_encrypt";
    
    static final String BANK_KG2KMK                 = "bank_kg2kmk";

    public static JSONDecryptionDecoder.DecryptionKeyHolder currentDecryptionKey;
    
    public static Vector<JSONDecryptionDecoder.DecryptionKeyHolder> decryptionKeys = 
            new Vector<JSONDecryptionDecoder.DecryptionKeyHolder>();
    
    public static final DataEncryptionAlgorithms dataEncryptionAlgorithm = 
            DataEncryptionAlgorithms.JOSE_A128CBC_HS256_ALG_ID;
    
    public static X509Certificate[] bankCertificatePath;

    public static ServerX509Signer bankKey;

    public static String bankCommonName;

    /////////////////////////////////////////////////////////////////////////////
    // Saturn service objects
    /////////////////////////////////////////////////////////////////////////////
    public static JSONDecoderCache knownPayeeMethods = new JSONDecoderCache();

    public static JSONDecoderCache knownAccountTypes = new JSONDecoderCache();

    static final String PAYMENT_ROOT                = "payment_root";

    static final String ACQUIRER_ROOT               = "acquirer_root";

    public static JSONX509Verifier paymentRoot;

    public static JSONX509Verifier acquirerRoot;

    public static String serviceUrl;

    public static String providerAuthorityUrl;

    static final int PROVIDER_EXPIRATION_TIME = 3600;
   
    /////////////////////////////////////////////////////////////////////////////
    // KeyGen2 objects
    /////////////////////////////////////////////////////////////////////////////
    public static JSONDecoderCache keygen2JSONCache;

    static final String VERSION_CHECK               = "android_webpki_versions";

    static final String TLS_CERTIFICATE             = "server_tls_certificate";

    public static X509Certificate serverCertificate;

    public static String grantedVersions;
    
    public static String keygen2RunUrl;

    public static KeyStoreEnumerator keyManagementKey;

    static final String SVG_CARD_IMAGE              = "svg_card_image";

    public static String svgCardImage;

    public static KeyPair carrierCaKeyPair;

    /////////////////////////////////////////////////////////////////////////////
    // Open Banking objects
    /////////////////////////////////////////////////////////////////////////////
    public static String oauth2ClientId;
    
    public static String oauth2ClientSecret;

    static final String OAUTH2_CLIENT_ID            = "oauth2_client_id";
    
    static final String OAUTH2_CLIENT_SECRET        = "oauth2_client_secret";

    static final String SATURN_EXTENSIONS           = "saturn_extensions";

    /////////////////////////////////////////////////////////////////////////////
    // Provider objects
    /////////////////////////////////////////////////////////////////////////////
    public static AuthorityObjectManager authorityObjectManager;

    static JSONObjectReader optionalProviderExtensions;

    /////////////////////////////////////////////////////////////////////////////
    // W3C PaymentRequest data
    /////////////////////////////////////////////////////////////////////////////
    static final String W3C_PAYMENT_REQUEST_URL   = "w3c_payment_request_url";

    public static String w3cPaymentRequestUrl;

    static final String USE_W3C_PAYMENT_REQUEST   = "use_w3c_payment_request";

    public static boolean useW3cPaymentRequest;

    /////////////////////////////////////////////////////////////////////////////
    // Miscellaneous
    /////////////////////////////////////////////////////////////////////////////
    public static DataSource jdbcDataSource;
    
    public static ExternalCalls externalCalls;

    InputStream getResource(String name) throws IOException {
        InputStream is = this.getClass().getResourceAsStream(getPropertyString(name));
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

    JSONX509Verifier getRoot(String name) throws IOException, GeneralSecurityException {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load (null, null);
        keyStore.setCertificateEntry("mykey",
                                     CertificateUtil.getCertificateFromBlob (
                                             getEmbeddedResourceBinary(name)));        
        return new JSONX509Verifier(new KeyStoreVerifier(keyStore));
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
    }

    @Override
    public void contextInitialized(ServletContextEvent event) {
        initProperties(event);
        try {
            /////////////////////////////////////////////////////////////////////////////////////////////
            // Logging?
            /////////////////////////////////////////////////////////////////////////////////////////////
            logging = getPropertyBoolean(LOGGING);

            /////////////////////////////////////////////////////////////////////////////////////////////
            // Core Open Banking/OAuth2 elements
            /////////////////////////////////////////////////////////////////////////////////////////////
            oauth2ClientId = getPropertyString(OAUTH2_CLIENT_ID);
            oauth2ClientSecret = getPropertyString(OAUTH2_CLIENT_SECRET);
            
            /////////////////////////////////////////////////////////////////////////////////////////////
            // Test merchant
            /////////////////////////////////////////////////////////////////////////////////////////////
            testMerchantUrl = getPropertyString(TEST_MERCHANT_URL);

            /////////////////////////////////////////////////////////////////////////////////////////////
            // Where our app resides in Cyberspace
            /////////////////////////////////////////////////////////////////////////////////////////////
            bankBaseUrl = getPropertyString(BANK_BASE_URL);

            /////////////////////////////////////////////////////////////////////////////////////////////
            // Payment network root keys
            /////////////////////////////////////////////////////////////////////////////////////////////
            paymentRoot = getRoot(PAYMENT_ROOT);
            acquirerRoot = getRoot(ACQUIRER_ROOT);

            /////////////////////////////////////////////////////////////////////////////////////////////
            // Payment network support
            /////////////////////////////////////////////////////////////////////////////////////////////
            knownPayeeMethods.addToCache(org.payments.sepa.SEPAPaymentBackendMethodDecoder.class);
            knownAccountTypes.addToCache(org.payments.sepa.SEPAAccountDataDecoder.class);

            /////////////////////////////////////////////////////////////////////////////////////////////
            // Bank specific
            /////////////////////////////////////////////////////////////////////////////////////////////
            bankCommonName = getPropertyString(BANK_COMMON_NAME);
            KeyStoreEnumerator bankcreds = 
                    new KeyStoreEnumerator(getResource(BANK_EECERT),
                                           getPropertyString(KEYSTORE_PASSWORD));
            bankCertificatePath = bankcreds.getCertificatePath();
            bankKey = new ServerX509Signer(bankcreds);

            KeyStoreEnumerator keyStoreEnumerator =
                    new KeyStoreEnumerator(getResource(BANK_ENCRYPT),
                                           getPropertyString(KEYSTORE_PASSWORD));
            currentDecryptionKey = new JSONDecryptionDecoder.DecryptionKeyHolder(
                    keyStoreEnumerator.getPublicKey(),
                    keyStoreEnumerator.getPrivateKey(),
                    keyStoreEnumerator.getPublicKey() instanceof RSAKey ?
                                                 KeyEncryptionAlgorithms.JOSE_RSA_OAEP_256_ALG_ID
                                                                        :
                                                 KeyEncryptionAlgorithms.JOSE_ECDH_ES_ALG_ID,
                    null);
            decryptionKeys.add(currentDecryptionKey);

            ////////////////////////////////////////////////////////////////////////////////////////////
            // KeyGen2 objects
            ////////////////////////////////////////////////////////////////////////////////////////////
            keygen2JSONCache = new JSONDecoderCache();
            keygen2JSONCache.addToCache(InvocationResponseDecoder.class);
            keygen2JSONCache.addToCache(ProvisioningInitializationResponseDecoder.class);
            keygen2JSONCache.addToCache(CredentialDiscoveryResponseDecoder.class);
            keygen2JSONCache.addToCache(KeyCreationResponseDecoder.class);
            keygen2JSONCache.addToCache(ProvisioningFinalizationResponseDecoder.class);
            
            keygen2RunUrl = bankBaseUrl + "/kg2.runner";

            svgCardImage = getEmbeddedResourceString(SVG_CARD_IMAGE);

            ////////////////////////////////////////////////////////////////////////////////////////////
            // Create a CA keys.  Note Saturn payment credentials do not use PKI
            ////////////////////////////////////////////////////////////////////////////////////////////
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec eccgen = new ECGenParameterSpec(KeyAlgorithms.NIST_P_256.getJceName());
            generator.initialize(eccgen, new SecureRandom());
            carrierCaKeyPair = generator.generateKeyPair();

            ////////////////////////////////////////////////////////////////////////////////////////////
            // SKS key management key
            ////////////////////////////////////////////////////////////////////////////////////////////
            keyManagementKey = new KeyStoreEnumerator(getResource(BANK_KG2KMK),
                                                      getPropertyString(KEYSTORE_PASSWORD));

            ////////////////////////////////////////////////////////////////////////////////////////////
            // Android WebPKI version check (vlow-vhigh)
            ////////////////////////////////////////////////////////////////////////////////////////////
            grantedVersions = getPropertyString(VERSION_CHECK);

            ////////////////////////////////////////////////////////////////////////////////////////////
            // Get TLS server certificate
            ////////////////////////////////////////////////////////////////////////////////////////////
            serverCertificate = CertificateUtil.getCertificateFromBlob(
                    ArrayUtil.readFile(getPropertyString(TLS_CERTIFICATE)));

            /////////////////////////////////////////////////////////////////////////////////////////////
            // Saturn extensions
            /////////////////////////////////////////////////////////////////////////////////////////////
            String extensions = getEmbeddedResourceString(SATURN_EXTENSIONS);
            if (!extensions.isEmpty()) {
                extensions = extensions.replace("${host}", bankBaseUrl);
                optionalProviderExtensions = JSONParser.parse(extensions);
            }

            ////////////////////////////////////////////////////////////////////////////////////////////
            // W3C PaymentRequest data
            ////////////////////////////////////////////////////////////////////////////////////////////
            useW3cPaymentRequest = getPropertyBoolean(USE_W3C_PAYMENT_REQUEST);
            w3cPaymentRequestUrl = getPropertyString(W3C_PAYMENT_REQUEST_URL);

            ////////////////////////////////////////////////////////////////////////////////////////////
            // Database
            ////////////////////////////////////////////////////////////////////////////////////////////
            Context initContext = new InitialContext();
            Context envContext  = (Context)initContext.lookup("java:/comp/env");
            jdbcDataSource = (DataSource)envContext.lookup("jdbc/SWEDBANK_SATURN");

            /////////////////////////////////////////////////////////////////////////////////////////////
            // Provider authority object
            /////////////////////////////////////////////////////////////////////////////////////////////
            authorityObjectManager = new AuthorityObjectManager(
                providerAuthorityUrl = bankBaseUrl + "/prv.authority",
                bankBaseUrl,
                serviceUrl = bankBaseUrl + "/sat.service",
                new ProviderAuthority.PaymentMethodDeclarations()
                    .add(new ProviderAuthority
                            .PaymentMethodDeclaration(
                                    PaymentMethods.BANK_DIRECT.getPaymentMethodUri())
                        .add(org.payments.sepa.SEPAPaymentBackendMethodDecoder.class))
                    .add(new ProviderAuthority
                            .PaymentMethodDeclaration(
                                    PaymentMethods.SUPER_CARD.getPaymentMethodUri())
                        .add(org.payments.sepa.SEPAPaymentBackendMethodDecoder.class)),
                optionalProviderExtensions,
                new SignatureProfiles[]{SignatureProfiles.P256_ES256},
                new ProviderAuthority.EncryptionParameter[]{
                        new ProviderAuthority.EncryptionParameter(
                                dataEncryptionAlgorithm,
                                currentDecryptionKey.getKeyEncryptionAlgorithm(), 
                                currentDecryptionKey.getPublicKey())},
                null,
                bankKey,

                null,
                null,

                PROVIDER_EXPIRATION_TIME,
                logging);

            /////////////////////////////////////////////////////////////////////////////////////////////
            // Generic Saturn call facility
            /////////////////////////////////////////////////////////////////////////////////////////////
            externalCalls = new ExternalCalls(logging, logger, null);

            /////////////////////////////////////////////////////////////////////////////////////////////
            // Finally, at each restart OAuth tokens for every enroll user must be checked for
            // validity and potentially be refreshed.
            //
            // For our Swedbank demo having a single use this is no big deal...
            /////////////////////////////////////////////////////////////////////////////////////////////
            OpenBanking.initialize();

            logger.info("Swedbank LIS Demo Successfully Initiated");
        } catch (Exception e) {
            logger.log(Level.SEVERE, "********\n" + e.getMessage() + "\n********", e);
        }
    }
}
