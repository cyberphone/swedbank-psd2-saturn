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

import javax.servlet.http.HttpServletRequest;

import org.webpki.json.JSONObjectReader;

import org.webpki.saturn.common.Currencies;


public class OpenBanking implements Serializable {
    
     public OpenBanking(String userId,
                        String clientIpAddress,
                        String userAgentOrNull) {
        this.userId = userId;
        this.clientIpAddress = clientIpAddress;
        this.userAgent = userAgent == null ? APICore.DEFAULT_BROWSER : userAgent;
    }

    public OpenBanking(String userId, HttpServletRequest request) {
        this(userId, 
             request.getRemoteAddr(),
             request.getHeader(APICore.HTTP_HEADER_USER_AGENT));
    }

    private static final long serialVersionUID = 1L;

    String userId;
    
    String userAgent;

    String clientIpAddress;

    String oauth2Token;

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
    
    public Object getUserObject() {
        return userObject;
    }
    
    public OpenBanking setUserObject(Object userObject) {
        this.userObject = userObject;
        return this;
    }

    public OpenBanking authorize() throws IOException {
        APICore.emulatedAuthorize(this);
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
}
