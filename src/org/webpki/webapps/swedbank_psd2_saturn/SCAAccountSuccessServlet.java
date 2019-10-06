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
package org.webpki.webapps.swedbank_psd2_saturn;

import java.io.IOException;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.json.JSONObjectReader;

import org.webpki.net.HTTPSWrapper;

public class SCAAccountSuccessServlet extends RESTBaseServlet {
    
    private static final long serialVersionUID = 1L;
    
    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws IOException, ServletException {
        ////////////////////////////////////////////////////////////////////////////////
        // Successful return after SCA (a dummy in the Sandbox)                       //
        ////////////////////////////////////////////////////////////////////////////////
        if (LocalIntegrationService.logging) {
            logger.info("Successful return after SCA");
        }
        HTTPSWrapper scaStatus = getHTTPSWrapper();
        scaStatus.setHeader(HTTP_HEADER_X_REQUEST_ID, String.valueOf(X_Request_ID++));
        setConsentId(scaStatus);
        setAuthorization(scaStatus);
        RESTUrl restUrl = new RESTUrl(scaStatusUrl)
            .setBic()
            .setAppId();
        scaStatus.makeGetRequest(restUrl.toString());
        logger.info("SCA Status:\n" + getJsonData(scaStatus).toString());
        
        HTTPSWrapper consentStatus = getHTTPSWrapper();
        consentStatus.setHeader(HTTP_HEADER_X_REQUEST_ID, String.valueOf(X_Request_ID++));
        setConsentId(consentStatus);
        setAuthorization(consentStatus);
        restUrl = new RESTUrl(OPEN_BANKING_HOST + "/sandbox/v2/consents/" + consentId)
            .setBic()
            .setAppId();
        consentStatus.makeGetRequest(restUrl.toString());
        logger.info("SCA Status:\n" + getJsonData(consentStatus).toString());

        restUrl = new RESTUrl(OPEN_BANKING_HOST + "/sandbox/v2/accounts/" + 
 //                targetAccountId  + "/balances")
 "AsdF01234EfgH4567"  + "/balances")
           .setBic()
            .setAppId();
        HTTPSWrapper wrapper = getHTTPSWrapper();
        wrapper.setHeader(HTTP_HEADER_X_REQUEST_ID, String.valueOf(X_Request_ID++));
        setConsentId(wrapper);
        setAuthorization(wrapper);
        logger.info(restUrl.toString());
        wrapper.makeGetRequest(restUrl.toString());
        JSONObjectReader json = getJsonData(wrapper);

        response.sendRedirect("home");
    }
}
