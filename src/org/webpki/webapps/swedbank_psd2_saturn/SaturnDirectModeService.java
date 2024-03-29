/*
 *  Copyright 2015-2020 WebPKI.org (http://webpki.org).
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

import java.util.ArrayList;
import java.util.LinkedHashMap;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.Context;
import javax.naming.InitialContext;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import javax.sql.DataSource;

import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.KeyStoreVerifier;
import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.KeyEncryptionAlgorithms;

import org.webpki.json.JSONCryptoHelper;
import org.webpki.json.JSONDecoderCache;
import org.webpki.json.JSONDecryptionDecoder;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONParser;
import org.webpki.json.JSONX509Verifier;

import org.webpki.util.ArrayUtil;

import org.webpki.saturn.common.AuthorityObjectManager;
import org.webpki.saturn.common.ExternalCalls;
import org.webpki.saturn.common.KeyStoreEnumerator;
import org.webpki.saturn.common.PaymentMethods;
import org.webpki.saturn.common.ProviderAuthorityDecoder;
import org.webpki.saturn.common.ServerX509Signer;
import org.webpki.saturn.common.SignatureProfiles;

import org.webpki.webutil.InitPropertyReader;

import org.webpki.webapps.swedbank_psd2_saturn.api.OpenBanking;
import org.webpki.webapps.swedbank_psd2_saturn.kg2.KeyProviderInitServlet;

// This is the starting point for the Direct Mode service

public class SaturnDirectModeService extends InitPropertyReader implements ServletContextListener {

    static Logger logger = Logger.getLogger(SaturnDirectModeService.class.getName());

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
    
    public static ArrayList<JSONDecryptionDecoder.DecryptionKeyHolder> decryptionKeys = 
            new ArrayList<>();
    
    public static final ContentEncryptionAlgorithms dataEncryptionAlgorithm = 
            ContentEncryptionAlgorithms.A128CBC_HS256;
    
    public static final JSONCryptoHelper.Options AUTHORIZATION_SIGNATURE_POLICY = 
            new JSONCryptoHelper.Options();
    
    static {
        AUTHORIZATION_SIGNATURE_POLICY.setPublicKeyOption(JSONCryptoHelper.PUBLIC_KEY_OPTIONS.REQUIRED);
        AUTHORIZATION_SIGNATURE_POLICY.setKeyIdOption(JSONCryptoHelper.KEY_ID_OPTIONS.FORBIDDEN);
    }
    
    public static X509Certificate[] bankCertificatePath;

    public static ServerX509Signer bankKey;

    public static String bankCommonName;

    /////////////////////////////////////////////////////////////////////////////
    // Saturn service objects
    /////////////////////////////////////////////////////////////////////////////
    public static JSONDecoderCache knownPayeeMethods = new JSONDecoderCache();

    public static JSONDecoderCache knownAccountTypes = new JSONDecoderCache();

    static final String BANK_NETWORK_ROOT           = "bank_network_root";

    static final String ACQUIRER_NETWORK_ROOT       = "acquirer_network_root";

    public static JSONX509Verifier bankNetworkRoot;

    public static JSONX509Verifier acquirerNetworkRoot;

    public static String serviceUrl;

    public static String providerAuthorityUrl;

    static final int PROVIDER_EXPIRATION_TIME = 3600;
   
    /////////////////////////////////////////////////////////////////////////////
    // KeyGen2 objects
    /////////////////////////////////////////////////////////////////////////////
    static final String ANDROID_WEBPKI_VERSIONS     = "android_webpki_versions";

    static final String ANDROID_CHROME_VERSION      = "android_chrome_version";

    static final String TLS_CERTIFICATE             = "server_tls_certificate";

    public static X509Certificate serverCertificate;

    public static String androidWebPkiVersions;
    
    public static int androidChromeVersion;

    public static String keygen2RunUrl;

    public static KeyStoreEnumerator keyManagementKey;
    
    public static String INHOUSE_LOGO                = "inhouse_logo";

    public static LinkedHashMap<String,String> cardImages = new LinkedHashMap<>();

    public static KeyPair carrierCaKeyPair;
    
    static final String BIOMETRIC_SUPPORT           = "biometric_support";
    
    public static boolean biometricSupport;

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
    static final String W3C_PAYMENT_REQUEST_URL     = "w3c_payment_request_url";

    public static String w3cPaymentRequestUrl;

    static final String USE_W3C_PAYMENT_REQUEST     = "use_w3c_payment_request";

    public static boolean useW3cPaymentRequest;

    /////////////////////////////////////////////////////////////////////////////
    // Miscellaneous
    /////////////////////////////////////////////////////////////////////////////
    public static DataSource jdbcDataSource;
    
    public static ExternalCalls externalCalls;

    InputStream getResource(String resourceName) throws IOException {
        InputStream is = this.getClass().getResourceAsStream(resourceName);
        if (is == null) {
            throw new IOException("Resource fail for: " + resourceName);
        }
        return is;
    }

    byte[] getEmbeddedResourceBinary(String resourceName) throws IOException {
        return ArrayUtil.getByteArrayFromInputStream(getResource(resourceName));
    }

    String getEmbeddedResourceString(String resourceName) throws IOException {
        return new String(getEmbeddedResourceBinary(resourceName), "utf-8");
    }

    void addCardImage(String cardTypeName) throws IOException {
        String cardImage = getEmbeddedResourceString("swedbank-" + cardTypeName + ".svg");
        if (getPropertyBoolean(INHOUSE_LOGO)) {
            cardImage = cardImage.replace("</svg>", getEmbeddedResourceString("inhouse-flag.txt"));
        }
        cardImage = cardImage.replace("\n", "");
        cardImages.put(cardTypeName, cardImage);
    }

    JSONX509Verifier getRoot(String propertyName) throws IOException, GeneralSecurityException {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load (null, null);
        keyStore.setCertificateEntry(
                "mykey",
                CertificateUtil.getCertificateFromBlob (
                        getEmbeddedResourceBinary(getPropertyString(propertyName))));        
        return new JSONX509Verifier(new KeyStoreVerifier(keyStore));
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
    }

    @Override
    public void contextInitialized(ServletContextEvent event) {
        initProperties(event);
        CustomCryptoProvider.forcedLoad(false);
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
            bankNetworkRoot = getRoot(BANK_NETWORK_ROOT);
            acquirerNetworkRoot = getRoot(ACQUIRER_NETWORK_ROOT);

            /////////////////////////////////////////////////////////////////////////////////////////////
            // Payment network support
            /////////////////////////////////////////////////////////////////////////////////////////////
            knownPayeeMethods.addToCache(se.bankgirot.BGAccountDataDecoder.class);
            knownAccountTypes.addToCache(org.payments.sepa.SEPAAccountDataDecoder.class);

            /////////////////////////////////////////////////////////////////////////////////////////////
            // Bank specific
            /////////////////////////////////////////////////////////////////////////////////////////////
            bankCommonName = getPropertyString(BANK_COMMON_NAME);
            KeyStoreEnumerator bankcreds = 
                    new KeyStoreEnumerator(getResource(getPropertyString(BANK_EECERT)),
                                           getPropertyString(KEYSTORE_PASSWORD));
            bankCertificatePath = bankcreds.getCertificatePath();
            bankKey = new ServerX509Signer(bankcreds);

            KeyStoreEnumerator keyStoreEnumerator =
                    new KeyStoreEnumerator(getResource(getPropertyString(BANK_ENCRYPT)),
                                           getPropertyString(KEYSTORE_PASSWORD));
            currentDecryptionKey = new JSONDecryptionDecoder.DecryptionKeyHolder(
                    keyStoreEnumerator.getPublicKey(),
                    keyStoreEnumerator.getPrivateKey(),
                    keyStoreEnumerator.getPublicKey() instanceof RSAKey ?
                                                 KeyEncryptionAlgorithms.RSA_OAEP_256
                                                                        :
                                                 KeyEncryptionAlgorithms.ECDH_ES,
                    null);
            decryptionKeys.add(currentDecryptionKey);

            ////////////////////////////////////////////////////////////////////////////////////////////
            // KeyGen2 objects
            ////////////////////////////////////////////////////////////////////////////////////////////
            biometricSupport = getPropertyBoolean(BIOMETRIC_SUPPORT);
            keygen2RunUrl = bankBaseUrl + "/kg2.runner";
            keyManagementKey = new KeyStoreEnumerator(getResource(getPropertyString(BANK_KG2KMK)),
                                                      getPropertyString(KEYSTORE_PASSWORD));
            addCardImage(KeyProviderInitServlet.METALCARD_PARM);
            addCardImage(KeyProviderInitServlet.WHITECARD_PARM);

            ////////////////////////////////////////////////////////////////////////////////////////////
            // Create a CA keys.  Payment credentials only use keys but KeyGen2 wraps keys in PKI
            ////////////////////////////////////////////////////////////////////////////////////////////
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec(KeyAlgorithms.P_256.getJceName()),
                                 new SecureRandom());
            carrierCaKeyPair = generator.generateKeyPair();

            ////////////////////////////////////////////////////////////////////////////////////////////
            // Android WebPKI version check (vlow-vhigh)
            ////////////////////////////////////////////////////////////////////////////////////////////
            androidWebPkiVersions = getPropertyString(ANDROID_WEBPKI_VERSIONS);

            ////////////////////////////////////////////////////////////////////////////////////////////
            // Android Chrome version check
            ////////////////////////////////////////////////////////////////////////////////////////////
            androidChromeVersion = getPropertyInt(ANDROID_CHROME_VERSION);

            ////////////////////////////////////////////////////////////////////////////////////////////
            // Get TLS server certificate
            ////////////////////////////////////////////////////////////////////////////////////////////
            serverCertificate = CertificateUtil.getCertificateFromBlob(
                    ArrayUtil.readFile(getPropertyString(TLS_CERTIFICATE)));

            /////////////////////////////////////////////////////////////////////////////////////////////
            // Saturn extensions
            /////////////////////////////////////////////////////////////////////////////////////////////
            String extensions = getEmbeddedResourceString(getPropertyString(SATURN_EXTENSIONS)).trim();
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
                "Swedbank/Open Banking",
                bankBaseUrl,
                bankBaseUrl + "/images/logotype.svg",
                serviceUrl = bankBaseUrl + "/sat.service",
                new ProviderAuthorityDecoder.PaymentMethodDeclarations()
                    .add(new ProviderAuthorityDecoder
                            .PaymentMethodDeclaration(
                                    PaymentMethods.BANK_DIRECT.getPaymentMethodUrl())
/*
                        .add(org.payments.sepa.SEPABackendPaymentDataDecoder.class))
                    .add(new ProviderAuthority
                            .PaymentMethodDeclaration(
                                    PaymentMethods.SUPER_CARD.getPaymentMethodUrl())
*/
                        .add(se.bankgirot.BGAccountDataDecoder.class)),
                optionalProviderExtensions,
                SignatureProfiles.values(),
                new ProviderAuthorityDecoder.EncryptionParameter[]{
                        new ProviderAuthorityDecoder.EncryptionParameter(
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
            // Finally, at each restart OAuth2 access tokens for every enrolled user must be checked for
            // validity and potentially be refreshed.
            //
            // For our Swedbank demo having a single user this is not such a big deal...
            /////////////////////////////////////////////////////////////////////////////////////////////
            OpenBanking.initialize();

            logger.info("Swedbank Saturn \"Direct Mode\" Demo Successfully Initiated");
        } catch (Exception e) {
            logger.log(Level.SEVERE, "********\n" + e.getMessage() + "\n********", e);
        }
    }
}
