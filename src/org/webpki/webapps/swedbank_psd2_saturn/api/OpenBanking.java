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
package org.webpki.webapps.swedbank_psd2_saturn.api;

import java.io.IOException;
import java.io.Serializable;

import java.math.BigDecimal;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import java.sql.SQLException;

import java.util.LinkedHashMap;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.webpki.json.JSONObjectReader;

import org.webpki.saturn.common.Currencies;

// This is the only class a normal application is supposed to use
// for accessing "Direct Mode" Open Banking methods.

public class OpenBanking implements Serializable {
    
    static Logger logger = Logger.getLogger(OpenBanking.class.getName());

    static class TokenRefresher extends Thread {
       
        long cycleTime;

        public TokenRefresher(long cycleTime) {
            this.cycleTime = cycleTime;
        }

        @Override
        public void run() {
            while (true) {
                try {
                    sleep(cycleTime);
                    performOneRefreshRound();
                } catch (Exception e) {
                    logger.log(Level.SEVERE, "Token update", e);
                }
            }
        }
    }
    
    public static class AuthenticationResult {
        String error;
        String humanName;
        String identityToken;

        public boolean failed() {
            return error != null;
        }

        public String getErrorMessage() {
            return error;
        }

        public String getHumanName() {
            return humanName;
        }
    }

    abstract static class CallBack {
        int updates;
        
        abstract void refreshToken(String identityToken, String refreshToken, int expires) throws IOException;
    }

    private OpenBanking(String clientIpAddress,
                        String userAgentOrNull) {
        this.clientIpAddress = clientIpAddress;
        this.userAgent = userAgentOrNull == null ? APICore.DEFAULT_BROWSER : userAgentOrNull;
    }
    
    OpenBanking(HttpServletRequest request) throws IOException {
        this(request.getRemoteAddr(),
             request.getHeader(APICore.HTTP_HEADER_USER_AGENT));
    }

    public OpenBanking(AuthenticationResult authenticationResult,
                       String clientIpAddress,
                       String userAgentOrNull) {
        this(clientIpAddress, userAgentOrNull);
        this.identityToken = authenticationResult.identityToken;
    }

    private static final long serialVersionUID = 1L;

    String userAgent;

    String clientIpAddress;

    String consentId;

    String scaStatusUrl;

    String statusUrl;
    
    String emulatorModeCookie;
    
    String paymentId;
    
    JSONObjectReader accountData;
    
    public JSONObjectReader getAccountData() {
        return accountData;
    }

    Object userObject;

    private Account currentAccount;

    String loginSuccessUrl;

    String identityToken;

    LinkedHashMap<String, Account> accounts;

    public Object getUserObject() {
        return userObject;
    }
    
    public OpenBanking setUserObject(Object userObject) {
        this.userObject = userObject;
        return this;
    }

    public Accounts basicAccountList() throws IOException {
        return APICore.emulatedAccountDataAccess(null, this);
    }

    public Accounts detailedAccountData(String[] accountIds) throws IOException {
        return APICore.emulatedAccountDataAccess(accountIds, this);
    }

    public String paymentRequest(String debtorAccount,
                                 String creditorAccount,
                                 BigDecimal amount,
                                 Currencies currency,
                                 String creditorName,
                                 String reference) throws IOException {
        return APICore.emulatedPaymentRequest(this, 
                                              debtorAccount,
                                              creditorAccount,
                                              amount,
                                              currency,
                                              creditorName,
                                              reference);
    }

    public OpenBanking authorize() throws IOException {
        APICore.emulatedAuthorize(this);
        return this;
    }

    public OpenBanking setRequestParameters(HttpServletRequest request) {
        request.getSession(true).setAttribute(APICore.OPEN_BANKING_SESSION_ATTR, this);
        return null;
    }

    public static OpenBanking getOpenBanking(HttpServletRequest request,
                                             HttpServletResponse response) throws IOException {
        return APICore.getOpenBanking(request, response);
    }


    public Account setAndValidateAccount(String accountId) {
        return currentAccount = accounts.get(accountId);
    }

    public String createCredential(String userName,
                                   String ipAddress,
                                   String paymentMethodUrl,
                                   PublicKey authorizationKey,
                                   PublicKey optionalBalanceRequestKey)
    throws SQLException, IOException, GeneralSecurityException {
        return DataBaseOperations.createCredential(identityToken,
                                                   currentAccount.accountId,
                                                   userName,
                                                   ipAddress,
                                                   paymentMethodUrl,
                                                   authorizationKey,
                                                   optionalBalanceRequestKey);
    }

    public static AuthenticationResult authenticatePayReq(String credentialId,
                                                          String accountId,
                                                          String paymentMethodUrl,
                                                          PublicKey authorizationKey)
    throws SQLException, IOException, GeneralSecurityException {
        return DataBaseOperations.authenticatePayReq(credentialId,
                                                     accountId,
                                                     paymentMethodUrl,
                                                     authorizationKey);
    }

    public static void createSession(HttpServletRequest request,
                                     HttpServletResponse response,
                                     String loginSuccessUrl) throws IOException {
        HttpSession session = request.getSession(true);
        OpenBanking openBanking = new OpenBanking(request);
        openBanking.loginSuccessUrl = loginSuccessUrl;
        session.setAttribute(APICore.OPEN_BANKING_SESSION_ATTR, openBanking);
        response.sendRedirect(APICore.coreInit());
    }

    static void performOneRefreshRound() throws IOException {
        final int time = (int) ((System.currentTimeMillis() + APICore.LIFETIME / 4) / 1000);
        CallBack callBack; 
        DataBaseOperations.scanAll(callBack = new CallBack() {

            @Override
            public void refreshToken(String identityToken,
                                     String refreshToken,
                                     int expires) throws IOException {
                if (expires < time) {
                    updates++;
                    OpenBanking temp = new OpenBanking(null, null);
                    temp.identityToken = identityToken;
                    APICore.getOAuth2Token(temp, true, refreshToken);
                }
            }
        });
        if (callBack.updates > 0) {
            logger.info("Updated " + callBack.updates + " tokens");
        }
    }

    public static void initialize() throws IOException {
        // Restart with fresh tokens if possible
        try {
           performOneRefreshRound();
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Restart problems", e);
        }
        // MUST always be running
        new TokenRefresher(APICore.LIFETIME / 10).start();
    }

    public Account getCurrentAccount() {
        return currentAccount;
    }

    public BigDecimal requestAccountBalance(String accountId) throws IOException {
        Accounts accounts = APICore.emulatedAccountDataAccess(new String[] {accountId}, this);
        return accounts.getAccount(accountId).getBalance();
    }

    public static AuthenticationResult authenticateBalReq(String credentialId,
                                                          String accountId,
                                                          PublicKey balanceKey)
    throws SQLException, IOException, GeneralSecurityException {
        return DataBaseOperations.authenticateBalReq(credentialId, accountId, balanceKey);
    }
}
