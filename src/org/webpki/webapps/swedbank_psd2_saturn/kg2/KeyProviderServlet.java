/*
 *  Copyright 2015-2018 WebPKI.org (http://webpki.org).
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

package org.webpki.webapps.swedbank_psd2_saturn.kg2;

import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;

import java.util.Date;
import java.util.Hashtable;

import java.util.logging.Level;
import java.util.logging.Logger;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.math.BigDecimal;
import java.math.BigInteger;

import java.net.URLEncoder;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.webpki.asn1.cert.DistinguishedName;

import org.webpki.ca.CA;
import org.webpki.ca.CertSpec;

import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.KeyUsageBits;
import org.webpki.crypto.SignatureWrapper;

import org.webpki.keygen2.ServerState;
import org.webpki.keygen2.KeySpecifier;
import org.webpki.keygen2.KeyGen2URIs;
import org.webpki.keygen2.InvocationResponseDecoder;
import org.webpki.keygen2.ProvisioningInitializationResponseDecoder;
import org.webpki.keygen2.CredentialDiscoveryResponseDecoder;
import org.webpki.keygen2.KeyCreationResponseDecoder;
import org.webpki.keygen2.ProvisioningFinalizationResponseDecoder;
import org.webpki.keygen2.InvocationRequestEncoder;
import org.webpki.keygen2.ProvisioningInitializationRequestEncoder;
import org.webpki.keygen2.CredentialDiscoveryRequestEncoder;
import org.webpki.keygen2.KeyCreationRequestEncoder;
import org.webpki.keygen2.ProvisioningFinalizationRequestEncoder;

import org.webpki.sks.Grouping;
import org.webpki.sks.AppUsage;
import org.webpki.sks.PassphraseFormat;

import org.webpki.saturn.common.AuthorizationData;
import org.webpki.saturn.common.BaseProperties;
import org.webpki.saturn.common.CardDataEncoder;
import org.webpki.saturn.common.CardImageData;
import org.webpki.saturn.common.PaymentMethods;

import org.webpki.util.MIMETypedObject;

import org.webpki.webutil.ServletUtil;

import org.webpki.json.DataEncryptionAlgorithms;
import org.webpki.json.JSONEncoder;
import org.webpki.json.JSONDecoder;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.KeyEncryptionAlgorithms;

import org.webpki.webapps.swedbank_psd2_saturn.LocalIntegrationService;
import org.webpki.webapps.swedbank_psd2_saturn.api.APICore;

// KeyGen2 protocol runner that creates Saturn wallet keys.

public class KeyProviderServlet extends APICore implements BaseProperties {

    private static final long serialVersionUID = 1L;

    static final int MAX_CARD_NAME_LENGTH = 30;  // Sorry :(
    static final int MAX_CARD_NAME_BIG    = 20;

    static Logger logger = Logger.getLogger(KeyProviderServlet.class.getCanonicalName());
    
    static String success_image_and_message;
    
    void returnKeyGen2Error(HttpServletResponse response, String errorMessage) throws IOException, ServletException {
        ////////////////////////////////////////////////////////////////////////////////////////////
        // Server errors are returned as HTTP redirects taking the client out of its KeyGen2 mode
        ////////////////////////////////////////////////////////////////////////////////////////////
        response.sendRedirect(LocalIntegrationService.keygen2RunUri + 
                              "?" +
                              KeyProviderInitServlet.ERROR_TAG +
                              "=" +
                              URLEncoder.encode(errorMessage, "UTF-8"));
    }
    
    void keygen2JSONBody(HttpServletResponse response, JSONEncoder object) throws IOException {
        byte[] jsonData = object.serializeJSONDocument(JSONOutputFormats.PRETTY_PRINT);
        if (LocalIntegrationService.logging) {
            logger.info("Sent message\n" + new String(jsonData, "UTF-8"));
        }
        response.setContentType(JSON_CONTENT_TYPE);
        response.setHeader("Pragma", "No-Cache");
        response.setDateHeader("EXPIRES", 0);
        response.getOutputStream().write(jsonData);
    }

    String certificateData(X509Certificate certificate) {
        return ", Subject='" + certificate.getSubjectX500Principal().getName() +
               "', Serial=" + certificate.getSerialNumber();
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
           throws IOException, ServletException {
logger.info("POST session=" + request.getSession(false).getId());
       executeRequest(request, response, false);
    }

    void executeRequest(HttpServletRequest request, HttpServletResponse response, boolean init)
         throws IOException, ServletException {
        HttpSession session = request.getSession(false);
        try {
            ////////////////////////////////////////////////////////////////////////////////////////////
            // Check that the request is properly authenticated
            ////////////////////////////////////////////////////////////////////////////////////////////
            if (session == null) {
                returnKeyGen2Error(response, "Session timed out");
                return;
             }
            ServerState keygen2State =
                (ServerState) session.getAttribute(KeyProviderInitServlet.KEYGEN2_SESSION_ATTR);
            if (keygen2State == null) {
                throw new IOException("Server state missing");
            }
            ////////////////////////////////////////////////////////////////////////////////////////////
            // Check if it is the first (trigger) message from the client
            ////////////////////////////////////////////////////////////////////////////////////////////
            if (init) {
                InvocationRequestEncoder invocationRequest = new InvocationRequestEncoder(keygen2State);
                keygen2State.addImageAttributesQuery(KeyGen2URIs.LOGOTYPES.LIST);
                keygen2JSONBody(response, invocationRequest);
                return;
              }

            ////////////////////////////////////////////////////////////////////////////////////////////
            // It should be a genuine KeyGen2 response.  Note that the order is verified!
            ////////////////////////////////////////////////////////////////////////////////////////////
            byte[] jsonData = ServletUtil.getData(request);
            if (!request.getContentType().equals(JSON_CONTENT_TYPE)) {
                throw new IOException("Wrong \"Content-Type\": " + request.getContentType());
            }
            if (LocalIntegrationService.logging) {
                logger.info("Received message:\n" + new String(jsonData, "UTF-8"));
            }
            JSONDecoder jsonObject = LocalIntegrationService.keygen2JSONCache.parse(jsonData);
            switch (keygen2State.getProtocolPhase()) {
                case INVOCATION:
                    InvocationResponseDecoder invocationResponse = (InvocationResponseDecoder) jsonObject;
                    keygen2State.update(invocationResponse);

                    // Now we really start doing something
                    ProvisioningInitializationRequestEncoder provisioningInitRequest =
                        new ProvisioningInitializationRequestEncoder(keygen2State,
                                                                       (short)1000,
                                                                       (short)50);
                    provisioningInitRequest.setKeyManagementKey(
                            LocalIntegrationService.keyManagementKey.getPublicKey());
                    keygen2JSONBody(response, provisioningInitRequest);
                    return;

                case PROVISIONING_INITIALIZATION:
                    ProvisioningInitializationResponseDecoder provisioningInitResponse = (ProvisioningInitializationResponseDecoder) jsonObject;
                    keygen2State.update(provisioningInitResponse);

                    logger.info("Device Certificate=" +
                            certificateData(keygen2State.getDeviceCertificate()));

                    ////////////////////////////////////////////////////////////////////////
                    // Finding out keys that should be deleted.  We don't want duplicate 
                    // payment credentials 
                    ////////////////////////////////////////////////////////////////////////
                    CredentialDiscoveryRequestEncoder credentialDiscoveryRequest =
                            new CredentialDiscoveryRequestEncoder(keygen2State);
                    credentialDiscoveryRequest.addLookupDescriptor(
                            LocalIntegrationService.keyManagementKey.getPublicKey());
                    keygen2JSONBody(response, credentialDiscoveryRequest);
                    return;

                case CREDENTIAL_DISCOVERY:
                    CredentialDiscoveryResponseDecoder credentiaDiscoveryResponse =
                        (CredentialDiscoveryResponseDecoder) jsonObject;
                    keygen2State.update(credentiaDiscoveryResponse);

                    ////////////////////////////////////////////////////////////////////////
                    // Mark keys for deletion
                    ////////////////////////////////////////////////////////////////////////
                    for (CredentialDiscoveryResponseDecoder.LookupResult lookupResult 
                           : 
                         credentiaDiscoveryResponse.getLookupResults()) {
                        for (CredentialDiscoveryResponseDecoder
                                .MatchingCredential matchingCredential
                                 : 
                             lookupResult.getMatchingCredentials()) {
                            X509Certificate endEntityCertificate = 
                                    matchingCredential.getCertificatePath()[0];
                            keygen2State
                                .addPostDeleteKey(matchingCredential.getClientSessionId(), 
                                                  matchingCredential.getServerSessionId(),
                                                  endEntityCertificate,
                                                  LocalIntegrationService.keyManagementKey.getPublicKey());
                          logger.info("Deleting key=" + certificateData(endEntityCertificate));
                        }
                    }

                    ////////////////////////////////////////////////////////////////////////
                    // Now order a set of new keys including suitable protection objects
                    ////////////////////////////////////////////////////////////////////////
                    ServerState.PINPolicy standardPinPolicy = 
                            keygen2State.createPINPolicy(PassphraseFormat.NUMERIC,
                                                         4,
                                                         8,
                                                         3,
                                                         null);
                    standardPinPolicy.setGrouping(Grouping.SHARED);

                    // Since Swedbank's "sandbox" doesn't support a dynamic account concept
                    // all testers must use the same key.
                    // For a fully dynamic solution, see the Saturn PoC.
                  
                    ServerState.Key key = 
                            keygen2State.createKey(AppUsage.SIGNATURE,
                                                   new KeySpecifier(KeyAlgorithms.NIST_P_256),
                                                   standardPinPolicy);                           
                    key.addEndorsedAlgorithm(AsymSignatureAlgorithms.ECDSA_SHA256);
                    key.setFriendlyName(LocalIntegrationService.bankCommonName);

                    keygen2JSONBody(response, new KeyCreationRequestEncoder(keygen2State));
                    return;

                case KEY_CREATION:
                    KeyCreationResponseDecoder keyCreationResponse = 
                        (KeyCreationResponseDecoder) jsonObject;
                    keygen2State.update(keyCreationResponse);

                    ////////////////////////////////////////////////////////////////////////
                    // Keys have been created, now add the data needed in order to make 
                    // them usable in Saturn as well
                    ////////////////////////////////////////////////////////////////////////
                    
                    // Note, user name is just an "alias"
                    // so it does NOT function as a user ID...
                    String userName = 
                            (String) session.getAttribute(KeyProviderInitServlet.USERNAME_SESSION_ATTR);
                    String credentialId;

                    // now create Saturn payment credentials
                    // 1. Get key
                    key = keygen2State.getKeys()[0];
/*
                    // 2. Create a "carrier" certificate for the signature key (SKS need that)
                    // In this unusual setup all certificates have the same public/private key.
                    CertSpec certSpec = new CertSpec();
                    certSpec.setKeyUsageBit(KeyUsageBits.DIGITAL_SIGNATURE);
                    certSpec.setSubject("CN=" + userName + ", serialNumber=" + credentialId);
                    Hashtable<String,String> issuer = new Hashtable<String,String>();
                    issuer.put("CN", "Saturn SKS Carrier Certificate");
                    long startTime = System.currentTimeMillis();
                    key.setCertificatePath(new X509Certificate[]{new CA().
                             createCert(certSpec,
                                        new DistinguishedName(issuer),
                                        BigInteger.ONE,
                                        new Date(startTime),
                                        new Date(startTime + (20 * 365 * 24 * 3600 * 1000l)),
                                        AsymSignatureAlgorithms.ECDSA_SHA256,
                                        new AsymKeySignerInterface() {

                                            @Override
                                            public PublicKey getPublicKey() throws IOException {
                                                return LocalIntegrationService
                                                           .carrierCaKeyPair.getPublic();
                                            }

                                            @Override
                                            public byte[] signData(
                                                    byte[] data,
                                                    AsymSignatureAlgorithms algorithm)
                                                    throws IOException {
                                                try {
                                                    return new SignatureWrapper(algorithm,
                                                                                LocalIntegrationService
                                                                     .carrierCaKeyPair.getPrivate())
                                                        .setEcdsaSignatureEncoding(true)
                                                        .update(data)
                                                        .sign();
                                                } catch (GeneralSecurityException e) {
                                                    throw new IOException(e);
                                                }
                                            }
                                        },
                                        LocalIntegrationService.fixedClientPaymentKey.getPublicKey())});
                    key.setPrivateKey(LocalIntegrationService.fixedClientPaymentKey.getPrivateKey()
                                                                                .getEncoded());

                    // 3. Add card data blob to the key entry
                    key.addExtension(BaseProperties.SATURN_WEB_PAY_CONTEXT_URI,
                            CardDataEncoder.encode(PaymentMethods.BANK_DIRECT.getPaymentMethodUri(),
                                                   credentialId, 
                                                   LocalIntegrationService.providerAuthorityUri, 
                                                   AsymSignatureAlgorithms.ECDSA_SHA256, 
                                                   DataEncryptionAlgorithms.JOSE_A128CBC_HS256_ALG_ID, 
                                                   KeyEncryptionAlgorithms.JOSE_ECDH_ES_ALG_ID, 
                                                   LocalIntegrationService.decryptionKey.getPublicKey(),
                                                   null,
                                                   null,
                                                   new BigDecimal("5302.00"))
                                                       .serializeToBytes(JSONOutputFormats.NORMALIZED));

                    // 4. Add personalized card image
                    key.addLogotype(KeyGen2URIs.LOGOTYPES.CARD, new MIMETypedObject() {

                        @Override
                        public byte[] getData() throws IOException {
                            String cardImage = new String(LocalIntegrationService.svgCardImage);
                            String cardUserName = userName;
                            if (cardUserName.length() > MAX_CARD_NAME_LENGTH) {
                                cardUserName = cardUserName.substring(0, MAX_CARD_NAME_LENGTH);
                            }
                            if (cardUserName.length() > MAX_CARD_NAME_BIG) {
                                cardImage = cardImage.replace(
                                        CardImageData.STANDARD_NAME_FONT_SIZE + 
                                            "\">" + 
                                            CardImageData.STANDARD_NAME,
                                        ((2 * CardImageData.STANDARD_NAME_FONT_SIZE) / 3) +
                                            "\">" + 
                                            CardImageData.STANDARD_NAME);
                            }
                            return cardImage
                                .replace(CardImageData.STANDARD_NAME, cardUserName)
                                .replace(CardImageData.STANDARD_ACCOUNT,credentialId)
                                    .getBytes("utf-8");
                        }

                        @Override
                        public String getMimeType() throws IOException {
                            return "image/svg+xml";
                        }
                       
                    });
*/
                    keygen2JSONBody(response, 
                                    new ProvisioningFinalizationRequestEncoder(keygen2State));
                    return;

                case PROVISIONING_FINALIZATION:
                    ProvisioningFinalizationResponseDecoder provisioningFinalResponse =
                        (ProvisioningFinalizationResponseDecoder) jsonObject;
                    keygen2State.update(provisioningFinalResponse);
                    logger.info("Successful KeyGen2 run");

                    ////////////////////////////////////////////////////////////////////////
                    // We are done, return an HTTP redirect taking 
                    // the client out of its KeyGen2 mode
                    ////////////////////////////////////////////////////////////////////////
                    response.sendRedirect(LocalIntegrationService.keygen2RunUri);
                    return;

                default:
                  throw new IOException("Unxepected state");
            }
        } catch (Exception e) {
            if (session != null) {
                session.invalidate();
            }
            logger.log(Level.SEVERE, "KeyGen2 failure", e);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PrintWriter printerWriter = new PrintWriter(baos);
            e.printStackTrace(printerWriter);
            printerWriter.flush();
            returnKeyGen2Error(response, baos.toString("UTF-8"));
        }
    }

    boolean foundData(HttpServletRequest request, StringBuilder result, String tag) {
        String value = request.getParameter(tag);
        if (value == null) {
            return false;
        }
        result.append(value);
        return true;
    }
    
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
           throws IOException, ServletException {
logger.info("GET session=" + request.getSession(false).getId() + " Q=" + request.getQueryString());
       if (request.getParameter(KeyProviderInitServlet.INIT_TAG) != null) {
            executeRequest(request, response, true);
            return;
        }
        StringBuilder html = new StringBuilder("<div class=\"label\">");
        StringBuilder result = new StringBuilder();
        if (foundData(request, result, KeyProviderInitServlet.ERROR_TAG)) {
            html.append("<table><tr><td>Failure Report:</td></tr><tr><td>" +
                        "<pre style=\"color:red;font-size:10pt\">")
                .append(result)
                .append("</pre></td></tr></table>");
        } else if (foundData(request, result, KeyProviderInitServlet.PARAM_TAG)) {
            html.append(result);
        } else if (foundData(request, result, KeyProviderInitServlet.ABORT_TAG)) {
            logger.info("KeyGen2 run aborted by the user");
            html.append("Aborted by the user!");
        } else {
            HttpSession session = request.getSession(false);
            if (session == null) {
                html.append("You need to restart the session");
            } else {
                session.invalidate();
                html.append("OK");
            }
        }
        KeyProviderInitServlet.output(response, 
                          KeyProviderInitServlet.getHTML(
                                 KeyProviderInitServlet.GO_HOME,
                                 null,
                                 html.append("</div>").toString()));
    }

}
