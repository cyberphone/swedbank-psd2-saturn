/*
 *  Copyright 2015-2019 WebPKI.org (http://webpki.org).
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
package org.webpki.webapps.swedbank_psd2_saturn.sat;

import java.io.IOException;

import java.math.BigDecimal;

import java.text.SimpleDateFormat;

import java.util.Locale;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;

import org.webpki.saturn.common.PayeeCoreProperties;
import org.webpki.saturn.common.UrlHolder;
import org.webpki.saturn.common.AuthorizationRequest;
import org.webpki.saturn.common.AuthorizationResponse;
import org.webpki.saturn.common.UserChallengeItem;
import org.webpki.saturn.common.PayeeAuthority;
import org.webpki.saturn.common.Currencies;
import org.webpki.saturn.common.AuthorizationData;
import org.webpki.saturn.common.PaymentRequest;
import org.webpki.saturn.common.ProviderAuthority;
import org.webpki.saturn.common.NonDirectPayments;
import org.webpki.saturn.common.Messages;
import org.webpki.saturn.common.UserResponseItem;

import org.webpki.util.ArrayUtil;

import org.webpki.util.ISODateTime;

import org.webpki.webapps.swedbank_psd2_saturn.LocalIntegrationService;

import org.webpki.webapps.swedbank_psd2_saturn.api.OpenBanking;

/////////////////////////////////////////////////////////////////////////////////
// This is the Saturn core Payment Provider (Bank) authorization servlet       //
/////////////////////////////////////////////////////////////////////////////////

public class AuthorizationServlet extends ProcessingBaseServlet {
  
    private static final long serialVersionUID = 1L;

    private static int testReferenceId;
    
    @Override
    JSONObjectWriter processCall(UrlHolder urlHolder,
                                 JSONObjectReader providerRequest) throws Exception {
 
        // Decode authorization request message
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(providerRequest);

        // Check that we actually were the intended party
        if (!LocalIntegrationService.serviceUrl.equals(authorizationRequest.getRecepientUrl())) {
            throw new IOException("Unexpected \"" + RECEPIENT_URL_JSON + "\" : " + authorizationRequest.getRecepientUrl());
        }

        // Verify that we understand the payment method
        AuthorizationRequest.PaymentBackendMethodDecoder paymentMethodSpecific =
            authorizationRequest.getPaymentBackendMethodSpecific(LocalIntegrationService.knownPayeeMethods);

        // Fetch the payment request object
        PaymentRequest paymentRequest = authorizationRequest.getPaymentRequest();
        NonDirectPayments nonDirectPayment = paymentRequest.getNonDirectPayment();
        boolean cardPayment = authorizationRequest.getPaymentMethod().isCardPayment();
        
        // Get the providers. Note that caching could play tricks on you!
        PayeeAuthority payeeAuthority;
        ProviderAuthority providerAuthority;
        boolean nonCached = false;
        while (true) {
            // Lookup of Payee
            urlHolder.setNonCachedMode(nonCached);
            payeeAuthority = 
                LocalIntegrationService.externalCalls.getPayeeAuthority(urlHolder,
                                                            authorizationRequest.getAuthorityUrl());

            // Lookup of Payee's Provider
            urlHolder.setNonCachedMode(nonCached);
            providerAuthority =
                LocalIntegrationService.externalCalls.getProviderAuthority(urlHolder,
                                                               payeeAuthority.getProviderAuthorityUrl());

            // Now verify that they are issued by the same entity
            if (payeeAuthority.getAttestationKey().equals(
                    providerAuthority.getHostingProvider() == null ?
                // Direct attestation of Payee
                providerAuthority.getSignatureDecoder().getCertificatePath()[0].getPublicKey()
                                                                   :
                // Indirect attestation of Payee through a designated Hosting provider
                providerAuthority.getHostingProvider().getPublicKey())) {
                break;
            }

            // No match, should we give up?
            if (nonCached) {
                throw new IOException("Payee attestation key mismatch");
            }
            
            // Edge case?  Yes, but it could happen
            nonCached = !nonCached;
        }

        // Verify that the authority objects were signed by a genuine payment partner
        providerAuthority.getSignatureDecoder().verify(cardPayment ? LocalIntegrationService.acquirerRoot : LocalIntegrationService.paymentRoot);

        // Verify Payee signature key.  It may be one generation back as well
        PayeeCoreProperties payeeCoreProperties = payeeAuthority.getPayeeCoreProperties();
        payeeCoreProperties.verify(paymentRequest.getPayee(), authorizationRequest.getSignatureDecoder());

        // Optionally verify the claimed Payee account
        byte[] accountHash = paymentMethodSpecific.getAccountHash();
        if (payeeCoreProperties.getAccountHashes() == null) {
            if (accountHash != null) {
                throw new IOException("Missing \"" + ACCOUNT_VERIFIER_JSON + 
                                      "\" in \"" + Messages.PAYEE_AUTHORITY.toString() + "\"");
            }
        } else {
            if (accountHash == null) {
                throw new IOException("Missing verifiable payee account");
            }
            boolean notFound = true;
            for (byte[] hash : payeeCoreProperties.getAccountHashes()) {
                if (ArrayUtil.compare(accountHash, hash)) {
                    notFound = false;
                    break;
                }
            }
            if (notFound) {
                throw new IOException("Payee account does not match \"" + ACCOUNT_VERIFIER_JSON + 
                                      "\" in \"" + Messages.PAYEE_AUTHORITY.toString() + "\"");
            }
        }

        // Decrypt and validate the encrypted Payer authorization
        AuthorizationData authorizationData = 
                authorizationRequest.getDecryptedAuthorizationData(
                        LocalIntegrationService.decryptionKeys);

        // Verify that the there is a matching Payer account
        //
        // Note: in this particular implementation the accountId coming
        // from the client is a unique id which in turn points to an
        // accountId for external consumption like an IBAN
        String credentialId = authorizationData.getAccountId();
        String authorizedPaymentMethod = authorizationData.getPaymentMethod();
        OpenBanking.AuthenticationResult authenticationResult =
                OpenBanking.authenticatePayReq(credentialId,
                                               authorizationData.getPublicKey());
        if (authenticationResult.failed()) {
            logger.severe(authenticationResult.getErrorMessage() + " " + credentialId + 
                    " " + authorizationData.getPublicKey().toString());
            throw new InternalException(authenticationResult.getErrorMessage());
        }
        String accountId = authenticationResult.getAccountId();

        // We don't accept requests that are old or ahead of time
        long diff = System.currentTimeMillis() - authorizationData.getTimeStamp().getTimeInMillis();
        if (diff > (MAX_CLIENT_CLOCK_SKEW + MAX_CLIENT_AUTH_AGE) || diff < -MAX_CLIENT_CLOCK_SKEW) {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.US);
            sdf.setTimeZone(authorizationData.getTimeStamp().getTimeZone());
            return createProviderUserResponse("Either your request is older than " + 
                                                (MAX_CLIENT_AUTH_AGE / 60000) +
                                                " minutes, or your device clock is incorrect.<p>Timestamp=" +
                                                "<span style=\"white-space:nowrap\">" + 
                                                sdf.format(authorizationData.getTimeStamp().getTime()) +
                                                "</span>.</p>",
                                              null,
                                              authorizationData);
        }
            
        ////////////////////////////////////////////////////////////////////////////
        // We got an authentic request.  Now we need to check available funds etc.//
        ////////////////////////////////////////////////////////////////////////////
        BigDecimal amount = paymentRequest.getAmount();

        // First we apply RBA v0.001...
        // Merchant provides the client's IP address which also could be used for RBA
        String clientIpAddress = authorizationRequest.getClientIpAddress();
        UserResponseItem userResponseItem;
        if (amount.compareTo(DEMO_RBA_LIMIT) >= 0 &&
            (((userResponseItem = authorizationData.getUserResponseItems().get(RBA_PARM_MOTHER)) == null) ||
            (!userResponseItem.getText().equals(MOTHER_NAME)))) {
            boolean specialTest = amount.compareTo(DEMO_RBA_LIMIT_CT) == 0;
            return createProviderUserResponse("Transaction requests exceeding " +
                                                amountInHtml(paymentRequest, DEMO_RBA_LIMIT) +
                                                " require additional user authentication to " +
                                                "be performed. Please enter your " +
                                                "<span style=\"color:blue\">mother's maiden name</span>." +
                                                "<br>&nbsp;<br>Since <i>this is a demo</i>, " +
                                                "answer <span style=\"color:red\">" + 
                                                MOTHER_NAME + 
                                                "</span>&nbsp;&#x1f642;",
              new UserChallengeItem[]{new UserChallengeItem(RBA_PARM_MOTHER,
                                                            specialTest ?
                                             UserChallengeItem.TYPE.ALPHANUMERIC
                                                                        : 
                                             UserChallengeItem.TYPE.ALPHANUMERIC_SECRET,
                                                            20,
                                                            specialTest ? 
                                                 "Mother's maiden name" : null)},
              authorizationData);
        }

        String transactionId;
        boolean testMode = authorizationRequest.getTestMode();
        String optionalLogData = null;
        if (testMode) {
            // In test mode we only authenticate using the "real" solution, the rest is "fake".
            transactionId = String.valueOf(testReferenceId++);
        }

        // Pure sample data...
        // Separate credit-card and account2account payments
        AuthorizationResponse.AccountDataEncoder accountData = cardPayment ?
            new com.supercard.SupercardAccountDataEncoder(
                    accountId, 
                    authenticationResult.getHumanName(),
                    ISODateTime.parseDateTime("2022-12-31T00:00:00Z", ISODateTime.COMPLETE))
                                                     :
            new org.payments.sepa.SEPAAccountDataEncoder(accountId);
                    
        // Note: for card payments we only use Saturn for SCA+ since Open Banking
        // does [currently] not support reservations
        if (cardPayment) {
            transactionId = "Card Authentication";
        } else {
            OpenBanking openBanking = new OpenBanking(authenticationResult,
                                                      authorizationRequest.getClientIpAddress(),
                                                      null);
            transactionId = openBanking.paymentRequest(accountId,
                                                       "BG 5051-6905",
                                                       amount,
                                                       paymentRequest.getCurrency(),
                                                       paymentRequest.getPayee().getCommonName(),
                                                       authorizationRequest.getReferenceId()
                                                           .replace('#', 'R'));
        }

        logger.info((testMode ? "TEST ONLY: ": "") +
                    "Authorized Amount=" + amount.toString() + 
                    ", Transaction ID=" + transactionId + 
                    ", Account ID=" + accountId + 
                    ", Payment Method=" + authorizedPaymentMethod + 
                    ", Client IP=" + clientIpAddress +
                    ", Method Specific=" + paymentMethodSpecific.logLine());

        // We did it!
        return AuthorizationResponse.encode(authorizationRequest,
                                            providerAuthority.getEncryptionParameters()[0],
                                            accountData,
                                            transactionId,
                                            optionalLogData,
                                            LocalIntegrationService.bankKey);
    }
}
