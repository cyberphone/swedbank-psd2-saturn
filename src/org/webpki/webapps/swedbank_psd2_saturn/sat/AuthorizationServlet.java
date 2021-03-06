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
package org.webpki.webapps.swedbank_psd2_saturn.sat;

import java.io.IOException;

import java.math.BigDecimal;

import java.text.SimpleDateFormat;

import java.util.Locale;

import javax.servlet.http.HttpServletRequest;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;

import org.webpki.saturn.common.PayeeCoreProperties;
import org.webpki.saturn.common.UrlHolder;
import org.webpki.saturn.common.AuthorizationRequestDecoder;
import org.webpki.saturn.common.AuthorizationResponseEncoder;
import org.webpki.saturn.common.NonDirectPaymentDecoder;
import org.webpki.saturn.common.UserChallengeItem;
import org.webpki.saturn.common.PayeeAuthorityDecoder;
import org.webpki.saturn.common.AccountDataDecoder;
import org.webpki.saturn.common.AccountDataEncoder;
import org.webpki.saturn.common.AuthorizationDataDecoder;
import org.webpki.saturn.common.PaymentRequestDecoder;
import org.webpki.saturn.common.ProviderAuthorityDecoder;
import org.webpki.saturn.common.UserResponseItem;

import org.webpki.util.ISODateTime;

import org.webpki.webapps.swedbank_psd2_saturn.SaturnDirectModeService;

import org.webpki.webapps.swedbank_psd2_saturn.api.OpenBanking;

/////////////////////////////////////////////////////////////////////////////////
// This is the Saturn core Payment Provider (Bank) authorization servlet       //
/////////////////////////////////////////////////////////////////////////////////

public class AuthorizationServlet extends ProcessingBaseServlet {
  
    private static final long serialVersionUID = 1L;

    private static int testReferenceId;
    
    @Override
    JSONObjectWriter processCall(UrlHolder urlHolder,
                                 JSONObjectReader providerRequest,
                                 HttpServletRequest httpServletRequest) throws Exception {
 
        // Decode authorization request message
        AuthorizationRequestDecoder authorizationRequest = new AuthorizationRequestDecoder(providerRequest);

        // Check that we actually were the intended party
        if (!SaturnDirectModeService.serviceUrl.equals(authorizationRequest.getRecipientUrl())) {
            throw new IOException("Unexpected \"" + RECIPIENT_URL_JSON + "\" : " + authorizationRequest.getRecipientUrl());
        }

        // Verify that we understand the backend payment method
        AccountDataDecoder payeeReceiveAccount =
            authorizationRequest.getPayeeReceiveAccount(SaturnDirectModeService.knownPayeeMethods);

        // Fetch the payment request object
        PaymentRequestDecoder paymentRequest = authorizationRequest.getPaymentRequest();

//TODO Current Open Banking APIs do not appear to support reservations
// so the following line doesn't have any real use...
        NonDirectPaymentDecoder nonDirectPayment = paymentRequest.getNonDirectPayment();
        if (nonDirectPayment != null) {
            throw new IOException("This implementation only support direct payments");
        }

        boolean cardPayment = authorizationRequest.getPaymentMethod().isCardPayment();
        
        // Get the providers. Note that caching could play tricks on you!
        PayeeAuthorityDecoder payeeAuthority;
        ProviderAuthorityDecoder providerAuthority;
        boolean nonCached = false;
        while (true) {
            // Lookup of Payee
            urlHolder.setNonCachedMode(nonCached);
            payeeAuthority = 
                SaturnDirectModeService.externalCalls
                    .getPayeeAuthority(urlHolder,
                                       authorizationRequest.getPayeeAuthorityUrl());

            // Lookup of Payee's Provider
            urlHolder.setNonCachedMode(nonCached);
            providerAuthority =
                SaturnDirectModeService.externalCalls
                    .getProviderAuthority(urlHolder,
                                          payeeAuthority.getProviderAuthorityUrl());

            // Now verify that the Payee is vouched for by a proper entity
            if (providerAuthority.checkPayeeKey(payeeAuthority)) {
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
        providerAuthority.getSignatureDecoder().verify(cardPayment ? 
                              SaturnDirectModeService.acquirerNetworkRoot :
                                  SaturnDirectModeService.bankNetworkRoot);

        // Verify Payee signature key.  It may be one generation back as well
        PayeeCoreProperties payeeCoreProperties = payeeAuthority.getPayeeCoreProperties();
        payeeCoreProperties.verify(authorizationRequest.getSignatureDecoder());

        // Optionally verify the claimed Payee account
        payeeCoreProperties.verifyAccount(payeeReceiveAccount);

        // Decrypt and validate the encrypted Payer authorization
        AuthorizationDataDecoder authorizationData = 
                authorizationRequest.getDecryptedAuthorizationData(
                        SaturnDirectModeService.decryptionKeys,
                        SaturnDirectModeService.AUTHORIZATION_SIGNATURE_POLICY);

        // Verify that the there is a matching Payer account
        //
        // In this particular implementation the accountId holds an IBAN
        // while credentialId holds a unique credential serial number.
        //
        // Since the issuer of a payment credential is also supposed to be
        // the consumer of it, this part is subject to customization.
        String accountId = authorizationData.getAccountId();
        String paymentMethodUrl = authorizationData.getPaymentMethodUrl();

        // Now, the most(?) important of all: verify that the key is recognized (=valid)
        OpenBanking.AuthenticationResult authenticationResult =
                OpenBanking.authenticatePayReq(authorizationData.getCredentialId(),
                                               accountId,
                                               paymentMethodUrl,
                                               authorizationData.getPublicKey());
        if (authenticationResult.failed()) {
            logger.severe(authenticationResult.getErrorMessage() + " " + accountId + 
                    " " + authorizationData.getPublicKey().toString());
            throw new InternalException(authenticationResult.getErrorMessage());
        }

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
            (!userResponseItem.getValue().equals(MOTHER_NAME)))) {
            boolean specialTest = amount.compareTo(DEMO_RBA_LIMIT_CT) == 0;
            return createProviderUserResponse("Transaction requests exceeding " +
                                                amountInHtml(paymentRequest, DEMO_RBA_LIMIT) +
                                                " require additional user authentication to " +
                                                "be performed. Please enter your " +
                                                "<span style='color:blue'>mother's maiden name</span>." +
                                                "<br>&nbsp;<br>Since <i>this is a demo</i>, " +
                                                "answer <span style='color:red'>" + 
                                                MOTHER_NAME + 
                                                "</span>&nbsp;&#x1f642;",
              new UserChallengeItem[]{new UserChallengeItem(RBA_PARM_MOTHER,
                                                            specialTest ?
                                             UserChallengeItem.TYPE.ALPHANUMERIC
                                                                        : 
                                             UserChallengeItem.TYPE.ALPHANUMERIC_SECRET,
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
        AccountDataEncoder accountData = cardPayment ?
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
                                                      payeeReceiveAccount.getAccountId(),
                                                      amount,
                                                      paymentRequest.getCurrency(),
                                                      paymentRequest.getPayeeCommonName(),
                                                      authorizationRequest.getReferenceId()
//TODO Swedbank consider '#' as an illegal character in references...
                                                          .replace('#', 'R'));
        }

        logger.info((testMode ? "TEST ONLY: ": "") +
                    "Authorized Amount=" + amount.toString() + 
                    ", Transaction ID=" + transactionId + 
                    ", Account ID=" + accountId + 
                    ", Payment Method=" + paymentMethodUrl + 
                    ", Client IP=" + clientIpAddress +
                    ", Method Specific=" + payeeReceiveAccount.logLine());

        // We did it!
        return AuthorizationResponseEncoder
                .encode(authorizationRequest,
                        providerAuthority.getEncryptionParameters()[0],
                        accountData,
                        accountData.getPartialAccountIdentifier(accountId),
                        transactionId,
                        optionalLogData,
                        SaturnDirectModeService.bankKey);
    }
}
