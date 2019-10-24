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

import org.webpki.json.JSONObjectReader;


public class OpenBankingSessionData implements Serializable {
    
    static final String DEFAULT_BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
           "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36";

    public OpenBankingSessionData(String userId, String clientIpAddress, String userAgent) {
        this.userId = userId;
        this.clientIpAddress = clientIpAddress;
        this.userAgent = userAgent == null ? DEFAULT_BROWSER : userAgent;
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
    
    public OpenBankingSessionData setUserObject(Object userObject) {
        this.userObject = userObject;
        return this;
    }
}
