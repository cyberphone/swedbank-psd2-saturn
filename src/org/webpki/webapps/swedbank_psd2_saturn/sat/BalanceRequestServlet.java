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

import java.math.BigDecimal;

import javax.servlet.http.HttpServletRequest;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;

import org.webpki.saturn.common.BalanceRequestDecoder;
import org.webpki.saturn.common.BalanceResponseEncoder;
import org.webpki.saturn.common.UrlHolder;

import org.webpki.webapps.swedbank_psd2_saturn.SaturnDirectModeService;

import org.webpki.webapps.swedbank_psd2_saturn.api.OpenBanking;


////////////////////////////////////////////////////////////////////////////////////////////////
// This is the Saturn balance request decoder servlet                                         //
////////////////////////////////////////////////////////////////////////////////////////////////

public class BalanceRequestServlet extends ProcessingBaseServlet {

    private static final long serialVersionUID = 1L;
    
    JSONObjectWriter processCall(UrlHolder urlHolder, 
                                 JSONObjectReader providerRequest,
                                 HttpServletRequest httpServletRequest) throws Exception {

        // Decode the balance request
        BalanceRequestDecoder balanceRequest = 
                new BalanceRequestDecoder(providerRequest,
                                          SaturnDirectModeService.AUTHORIZATION_SIGNATURE_POLICY);
        
        // The request parsed and the signature was (technically) correct, continue
        String credentialId = balanceRequest.getCredentialId();
        String accountId = balanceRequest.getAccountId();
        
        // Verify the authenticity of the key and get a handle to the user
        OpenBanking.AuthenticationResult authenticationResult = 
                OpenBanking.authenticateBalReq(credentialId,
                                               accountId,
                                               balanceRequest.getPublicKey());
        if (authenticationResult.failed()) {
            logger.severe(authenticationResult.getErrorMessage() + " " + accountId + 
                    " " + balanceRequest.getPublicKey().toString());
            throw new InternalException(authenticationResult.getErrorMessage());
        }
        
        // Succeeded, create an Open Banking session
        OpenBanking openBanking = new OpenBanking(authenticationResult,
                                                  httpServletRequest.getRemoteAddr(),
                                                  null);
 
        // Finally, call the bank
        BigDecimal balance = openBanking.requestAccountBalance(accountId);
        
        // We did it, now return the result to the "wallet"
        return BalanceResponseEncoder.encode(accountId, 
                                             balance, 
                                             balanceRequest.getCurrency());
    }
}
