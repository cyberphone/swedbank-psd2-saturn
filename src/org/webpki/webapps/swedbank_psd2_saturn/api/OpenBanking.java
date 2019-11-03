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
package org.webpki.webapps.swedbank_psd2_saturn.api;

import java.io.IOException;
import java.io.Serializable;

import java.math.BigDecimal;

import java.security.PublicKey;

import java.sql.SQLException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.webpki.json.JSONObjectReader;

import org.webpki.saturn.common.Currencies;

// This is the only class a normal application is supposed to use
// for accessing Dual-mode Open Banking methods.

public class OpenBanking implements Serializable {
    
    public static class AuthenticationResult {
        public String error;
        public String name;
        public String accountId;
        public String accessToken;
    }

    interface CallBack {
        void refreshToken(String userId, String refreshToken, int expires) throws IOException;
    }
    
    private OpenBanking(String clientIpAddress,
                        String userAgentOrNull) {
        this.clientIpAddress = clientIpAddress;
        this.userAgent = userAgentOrNull == null ? APICore.DEFAULT_BROWSER : userAgentOrNull;
    }
    
    public OpenBanking(HttpServletRequest request) throws IOException {
        this(request.getRemoteAddr(),
             request.getHeader(APICore.HTTP_HEADER_USER_AGENT));
    }

    public OpenBanking(AuthenticationResult authenticationResult,
                       String clientIpAddress,
                       String userAgentOrNull) {
        this(clientIpAddress, userAgentOrNull);
        this.accessToken = authenticationResult.accessToken;
    }

    private static final long serialVersionUID = 1L;

    String userAgent;

    String clientIpAddress;

    String accessToken;

    String refreshToken;
    
    long expires;
    
    String consentId;

    String scaStatusUrl;

    String statusUrl;
    
    String emulatorModeCookie;
    
    String paymentId;
    
    JSONObjectReader accountData;
    
    public JSONObjectReader getAccountData() {
        return accountData;
    }

    void consistencyCheck(boolean withBalance) throws IOException {
        if (withBalance && accountData == null) {
            throw new IOException("Wrong order of account data calls");
        }
    }
    
    Object userObject;

    private String currentAccountId;

    String loginSuccessUrl;

    String userId;

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

    public static void initialize() throws IOException {
        performOneRefreshRound();
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


    public void setAndValidateAccountId(String account) {
        currentAccountId = account;
    }

    public String getAccountId() {
        return currentAccountId;
    }

    public String createCredential(String userName,
                                   String methodUri,
                                   PublicKey payReq,
                                   PublicKey optionalBalReq)
    throws SQLException, IOException {
        return DataBaseOperations.createCredential(currentAccountId,
                                                   userName,
                                                   methodUri,
                                                   userId,
                                                   payReq,
                                                   optionalBalReq);
    }

    public static AuthenticationResult authenticatePayReq(String credentialId,
                                                          PublicKey payReq)
    throws SQLException, IOException {
        return DataBaseOperations.authenticatePayReq(credentialId, payReq);
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
        final int time = (int) ((System.currentTimeMillis() - APICore.LIFETIME / 3) / 1000);
        DataBaseOperations.scanAll(new CallBack() {

            @Override
            public void refreshToken(String userId,
                                     String refreshToken,
                                     int expires) throws IOException {
                if (expires < time) {
                    OpenBanking temp = new OpenBanking(null, null);
                    temp.userId = userId;
                    temp.refreshToken = refreshToken;
                    APICore.getOAuth2Token(temp, null);
                }
            }
        });
    }
}
