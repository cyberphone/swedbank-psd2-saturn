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
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONParser;

import org.webpki.net.HTTPSWrapper;

public class AuthRedirectServlet extends RESTBaseServlet {

    private static final long serialVersionUID = 1L;

    static final JSONObjectWriter consentData;

    static {
        try {
            consentData = new JSONObjectWriter(JSONParser.parse(
        "{" + 
          "\"access\": {" + 
            "\"accounts\": [" + 
              "{" + 
                "\"iban\": \"string\"" + 
              "}" + 
            "]," + 
            "\"availableAccounts\": \"allAccounts\"," + 
            "\"balances\": [" + 
              "{" + 
                "\"iban\": \"string\"" + 
              "}" + 
            "]," + 
            "\"transactions\": [" + 
              "{" + 
                "\"iban\": \"string\"" + 
              "}" + 
            "]" + 
          "}," + 
          "\"combinedServiceIndicator\": false," + 
          "\"frequencyPerDay\": 0," + 
          "\"recurringIndicator\": false," + 
          "\"validUntil\": \"2019-10-31\"" + 
        "}"));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    static int X_Request_ID = 1536;
    
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        ////////////////////////////////////////////////////////////////////////////////
        // This servlet is redirected to by the PSD2 service after a successful user  //
        // authentication                                                             //
        ////////////////////////////////////////////////////////////////////////////////
        String code = request.getParameter("code");
        if (code == null) {
            throw new IOException("Didn't find 'code' object");
        }
        if (LocalIntegrationService.logging) {
            logger.info("code=" + code);
        }
        
        ////////////////////////////////////////////////////////////////////////////////
        // We got the code, now we need to upgrade it to a oauth2 token               //
        ////////////////////////////////////////////////////////////////////////////////
        FormData formData = new FormData()
            .addElement("grant_type", "authorization_code")
            .addElement("client_id", LocalIntegrationService.oauth2ClientId)
            .addElement("client_secret", LocalIntegrationService.oauth2ClientSecret)
            .addElement("code", code)
            .addElement("redirect_uri", LocalIntegrationService.oauth2RedirectUri);
        HTTPSWrapper wrapper = getHTTPSWrapper();
        wrapper.makePostRequest(OPEN_BANKING_HOST + "/psd2/token", formData.toByteArray());
        JSONObjectReader json = getJsonData(wrapper);
        oauth2Token = json.getString("access_token");
        if (LocalIntegrationService.logging) {
            logger.info("access_token=" + oauth2Token);
        }

        ////////////////////////////////////////////////////////////////////////////////
        // We got the token, now we need a consent for our accounts                   //
        ////////////////////////////////////////////////////////////////////////////////
        getConsent(consentData, request);
        if (LocalIntegrationService.logging) {
            logger.info("consentId=" + consentId);
        }

        ////////////////////////////////////////////////////////////////////////////////
        // We got the consent, now use it!                                            //
        ////////////////////////////////////////////////////////////////////////////////
        RESTUrl restUrl = new RESTUrl(OPEN_BANKING_HOST + "/sandbox/v2/accounts")
            .setBic()
            .setAppId()
            .addParameter("withBalance", "true");
        wrapper = getHTTPSWrapper();
        wrapper.setHeader(HTTP_HEADER_X_REQUEST_ID, String.valueOf(X_Request_ID++));
        setConsentId(wrapper);
        setAuthorization(wrapper);
        wrapper.makeGetRequest(restUrl.toString());
        json = getJsonData(wrapper);
        response.sendRedirect("home");
    }
}
