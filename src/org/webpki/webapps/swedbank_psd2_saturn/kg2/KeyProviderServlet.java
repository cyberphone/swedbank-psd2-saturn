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

package org.webpki.webapps.swedbank_psd2_saturn.kg2;

import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;

import java.util.Date;
import java.util.Hashtable;

import java.util.logging.Level;
import java.util.logging.Logger;

import java.security.GeneralSecurityException;

import java.security.cert.X509Certificate;

import java.math.BigInteger;

import java.net.URLEncoder;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.webpki.asn1.cert.DistinguishedName;

import org.webpki.ca.CA;
import org.webpki.ca.CertSpec;

import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.KeyUsageBits;

import org.webpki.crypto.signatures.SignatureWrapper;

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
import org.webpki.sks.BiometricProtection;
import org.webpki.sks.PassphraseFormat;

import org.webpki.saturn.common.BaseProperties;
import org.webpki.saturn.common.CardDataEncoder;
import org.webpki.saturn.common.CardImageData;
import org.webpki.saturn.common.PaymentMethods;

import org.webpki.util.MIMETypedObject;

import org.webpki.webutil.ServletUtil;

import org.webpki.json.JSONEncoder;
import org.webpki.json.JSONDecoder;
import org.webpki.json.JSONOutputFormats;

import org.webpki.webapps.swedbank_psd2_saturn.HomeServlet;
import org.webpki.webapps.swedbank_psd2_saturn.HTML;
import org.webpki.webapps.swedbank_psd2_saturn.SaturnDirectModeService;

import org.webpki.webapps.swedbank_psd2_saturn.api.Account;
import org.webpki.webapps.swedbank_psd2_saturn.api.OpenBanking;

// KeyGen2 protocol runner that creates Saturn wallet keys.

public class KeyProviderServlet extends HttpServlet implements BaseProperties {

    private static final long serialVersionUID = 1L;

    static final int MAX_CARD_NAME_LENGTH = 30;  // Sorry :(
    static final int MAX_CARD_NAME_BIG    = 20;
    
    static final String CARD_IMAGE_ATTR   = "card";

    static Logger logger = Logger.getLogger(KeyProviderServlet.class.getCanonicalName());
    
    void returnKeyGen2Error(HttpServletResponse response, String errorMessage) throws IOException, ServletException {
        ////////////////////////////////////////////////////////////////////////////////////////////
        // Server errors are returned as HTTP redirects taking the client out of its KeyGen2 mode
        ////////////////////////////////////////////////////////////////////////////////////////////
        response.sendRedirect(SaturnDirectModeService.keygen2RunUrl + 
                              "?" +
                              KeyProviderInitServlet.ERROR_TAG +
                              "=" +
                              URLEncoder.encode(errorMessage, "UTF-8"));
    }
    
    void keygen2JSONBody(HttpServletResponse response, JSONEncoder object) 
            throws IOException, GeneralSecurityException {
        byte[] jsonData = object.serializeJSONDocument(JSONOutputFormats.PRETTY_PRINT);
        if (SaturnDirectModeService.logging) {
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
                if (SaturnDirectModeService.biometricSupport) {
                    keygen2State.addFeatureQuery(KeyGen2URIs.CLIENT_FEATURES.BIOMETRIC_SUPPORT);
                }
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
            if (SaturnDirectModeService.logging) {
                logger.info("Received message:\n" + new String(jsonData, "UTF-8"));
            }
            JSONDecoder jsonObject = ServerState.parseReceivedMessage(jsonData);
            switch (keygen2State.getProtocolPhase()) {
                case INVOCATION:
                    InvocationResponseDecoder invocationResponse = 
                        (InvocationResponseDecoder) jsonObject;
                    keygen2State.update(invocationResponse);

                    // Now we really start doing something
                    ProvisioningInitializationRequestEncoder provisioningInitRequest =
                        new ProvisioningInitializationRequestEncoder(keygen2State,
                                                                       (short)1000,
                                                                       (short)50);
                    provisioningInitRequest.setKeyManagementKey(
                            SaturnDirectModeService.keyManagementKey.getPublicKey());
                    keygen2JSONBody(response, provisioningInitRequest);
                    return;

                case PROVISIONING_INITIALIZATION:
                    ProvisioningInitializationResponseDecoder provisioningInitResponse = 
                        (ProvisioningInitializationResponseDecoder) jsonObject;
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
                            SaturnDirectModeService.keyManagementKey.getPublicKey());
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

// TODO 
// if the user already have (in the actual device) a credential for the
// selected account, it should be removed from the credential database
// but only if the rest of the enrollment process is successful.
//
// Note: all information required is available in the retrieved certificate:
// - Certificate serial number holds "CredentialId"
// - Subject serialNumber attribute holds "AccountId"

                            X509Certificate endEntityCertificate = 
                                    matchingCredential.getCertificatePath()[0];
                            keygen2State
                                .addPostDeleteKey(
                                    matchingCredential.getClientSessionId(), 
                                    matchingCredential.getServerSessionId(),
                                    endEntityCertificate,
                                    SaturnDirectModeService.keyManagementKey.getPublicKey());
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
                    // all testers use the same account but they get individual keys.
                    // For a fully dynamic solution, see the Saturn PoC.
                  
                    // Create the authorization key
                    ServerState.Key authKey = 
                            keygen2State.createKey(AppUsage.SIGNATURE,
                                                   new KeySpecifier(KeyAlgorithms.NIST_P_256),
                                                   standardPinPolicy);                           
                    authKey.addEndorsedAlgorithm(AsymSignatureAlgorithms.ECDSA_SHA256);
                    authKey.setFriendlyName(SaturnDirectModeService.bankCommonName);
                    if (keygen2State.isFeatureSupported(KeyGen2URIs.CLIENT_FEATURES.BIOMETRIC_SUPPORT)) {
                        authKey.setBiometricProtection(BiometricProtection.ALTERNATIVE);
                    }

                    // Then create the balance key
                    keygen2State.createKey(AppUsage.SIGNATURE,
                                           new KeySpecifier(KeyAlgorithms.NIST_P_256),
                                           null)
                        .setFriendlyName(SaturnDirectModeService.bankCommonName + " balance key");
 
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
                    String userName = (String) session.getAttribute(
                            KeyProviderInitServlet.USERNAME_SESSION_ATTR);
                    OpenBanking openBanking = OpenBanking.getOpenBanking(request, response);
                    Account account = openBanking.getCurrentAccount();
                    String accountId = account.getAccountId();

                    // Now create Saturn payment credentials

                    // 1. Get keys and other input data
                    authKey = keygen2State.getKeys()[0];
                    ServerState.Key balanceKey = keygen2State.getKeys()[1];
                    String paymentMethodUrl = PaymentMethods.BANK_DIRECT.getPaymentMethodUrl();
                    // A credentialId uniquely points to an account
                    String credentialId = openBanking.createCredential(userName,
                                                                       request.getRemoteAddr(),
                                                                       paymentMethodUrl,
                                                                       authKey.getPublicKey(),
                                                                       balanceKey.getPublicKey());

                    // 2. Create a "carrier" certificate for the authorization key (SKS need that)
                    createCarrierCerificate(authKey, userName, credentialId, accountId);

                    // 4. Create a "carrier" certificate for the balance key as well
                    createCarrierCerificate(balanceKey, userName, credentialId, accountId);

                    // 5. Add card data blob to the authorization key
                    authKey.addExtension(BaseProperties.SATURN_WEB_PAY_CONTEXT_URI,
                        CardDataEncoder.encode(
                            paymentMethodUrl,
                            credentialId,
                            accountId,
                            account.getCurrency(),
                            SaturnDirectModeService.providerAuthorityUrl, 
                            HashAlgorithms.SHA256,
                            AsymSignatureAlgorithms.ECDSA_SHA256, 
                            SaturnDirectModeService.dataEncryptionAlgorithm, 
                            SaturnDirectModeService.currentDecryptionKey.getKeyEncryptionAlgorithm(), 
                            SaturnDirectModeService.currentDecryptionKey.getPublicKey(),
                            null,
                            HashAlgorithms.SHA256.digest(balanceKey.getPublicKey().getEncoded()))
                                .serializeToBytes(JSONOutputFormats.NORMALIZED));

                    // 6. Add personalized card image
                    String cardImage = new String(
                            SaturnDirectModeService.cardImages.get(
                                    (String)session.getAttribute(
                                            KeyProviderInitServlet.CARDTYPE_SESSION_ATTR)));
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
                    final String completedCardImage = 
                            cardImage.replace(CardImageData.STANDARD_NAME, cardUserName)
                                     .replace(CardImageData.STANDARD_ACCOUNT, accountId);
                    session.setAttribute(CARD_IMAGE_ATTR, completedCardImage);
                    authKey.addLogotype(KeyGen2URIs.LOGOTYPES.CARD, new MIMETypedObject() {

                        @Override
                        public byte[] getData() throws IOException {
                            return completedCardImage.getBytes("utf-8");
                        }

                        @Override
                        public String getMimeType() throws IOException {
                            return "image/svg+xml";
                        }
                       
                    });
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
                    response.sendRedirect(SaturnDirectModeService.keygen2RunUrl);
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

    void createCarrierCerificate(ServerState.Key key, 
                                 String userName,
                                 String credentialId,
                                 String accountId) throws IOException, GeneralSecurityException {
        CertSpec certSpec = new CertSpec();
        certSpec.setKeyUsageBit(KeyUsageBits.DIGITAL_SIGNATURE);
        certSpec.setSubject("CN=" + userName + ", serialNumber=" + accountId);
        Hashtable<String, String> issuer = new Hashtable<>();
        issuer.put("CN", "Saturn SKS Carrier Certificate");
        long startTime = System.currentTimeMillis();
        key.setCertificatePath(new X509Certificate[] { new CA().createCert(
            certSpec, 
            new DistinguishedName(issuer),
            new BigInteger(credentialId), 
            new Date(startTime),
            new Date(startTime + (20 * 365 * 24 * 3600 * 1000l)), 
            new AsymKeySignerInterface() {

                @Override
                public byte[] signData(byte[] data) throws IOException, GeneralSecurityException {
                    return new SignatureWrapper(
                            getAlgorithm(), 
                            SaturnDirectModeService.carrierCaKeyPair.getPrivate())
                        .setEcdsaSignatureEncoding(true)
                        .update(data)
                        .sign();
                }

                @Override
                public AsymSignatureAlgorithms getAlgorithm() {
                    return AsymSignatureAlgorithms.ECDSA_SHA256;
                }

            }, 
            SaturnDirectModeService.carrierCaKeyPair.getPublic(),
            key.getPublicKey())
        });
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
       if (request.getParameter(KeyProviderInitServlet.INIT_TAG) != null) {
            executeRequest(request, response, true);
            return;
        }
        StringBuilder html = new StringBuilder();
        StringBuilder result = new StringBuilder();
        if (foundData(request, result, KeyProviderInitServlet.ERROR_TAG)) {
            html.append(
                    "<div class='centerbox'>" +
                      "<table><tr><td>Failure Report:</td></tr><tr><td>" +
                      "<pre style='color:red;font-size:10pt'>")
                .append(result)
                .append("</pre></td></tr></table>");
        } else if (foundData(request, result, KeyProviderInitServlet.PARAM_TAG)) {
            html.append(result);
        } else if (foundData(request, result, KeyProviderInitServlet.ABORT_TAG)) {
            logger.info("KeyGen2 run aborted by the user");
            html.append("<div class='header'>Aborted by the User!");
        } else {
            HttpSession session = request.getSession(false);
            if (session == null) {
                response.sendRedirect(HomeServlet.REDIRECT_TIMEOUT_URI);
                return;
            }
            String completedCardImage = (String) session.getAttribute(CARD_IMAGE_ATTR);
            session.invalidate();
            html.append("<div class='header'>Successful Enrollment!</div>")
                .append(CardImageData.viewableFormat(completedCardImage, "80%"))
                .append("<div class='centerbox'>" +
                          "<div class='description' style='padding-top:0.5em'>" +
                           "You may now pay with the card at a merchant like:<br>" +
                           "<a href='")
                .append(SaturnDirectModeService.testMerchantUrl)
                .append("'>")
                .append(SaturnDirectModeService.testMerchantUrl)
                .append("</a></div>");
        }
        HTML.standardPage(response,
                          null,
                          html.append("</div>"));
    }
}
