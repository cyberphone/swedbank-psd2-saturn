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

import java.net.URLEncoder;

import java.util.Date;
import java.util.Locale;

import java.util.logging.Logger;

import java.text.SimpleDateFormat;
import java.time.ZonedDateTime;
import java.time.ZoneOffset;

import java.time.format.DateTimeFormatter;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.net.HTTPSWrapper;

import org.webpki.saturn.common.BaseProperties;
import org.webpki.saturn.common.HttpSupport;


abstract class RESTBaseServlet extends HttpServlet {
    
    private static final long serialVersionUID = 1L;

    static final String OBSD                             = "obsd";
    
    static final String HTTP_HEADER_X_REQUEST_ID         = "X-Request-ID";
    static final String HTTP_HEADER_CONSENT_ID           = "Consent-ID";
    static final String HTTP_HEADER_AUTHORIZATION        = "Authorization";
    static final String HTTP_HEADER_PSU_IP_ADDRESS       = "PSU-IP-Address";
    static final String HTTP_HEADER_PSU_IP_PORT          = "PSU-IP-Port";
    static final String HTTP_HEADER_PSU_HTTP_METHOD      = "PSU-Http-Method";
    static final String HTTP_HEADER_PSU_USER_AGENT       = "PSU-User-Agent";
    static final String HTTP_HEADER_TTP_REDIRECT_URI     = "TPP-Redirect-URI";
    static final String HTTP_HEADER_TPP_NOK_REDIRECT_URI = "TPP-Nok-Redirect-URI";
    
    static final String OAUTH2_REDIRECT_PATH             = "/authredirect";
    static final String SCA_ACCOUNT_SUCCESS_PATH         = "/scaaccountsuccess";
    static final String SCA_FAILED_PATH                  = "/scafailed";

    static Logger logger = Logger.getLogger(RESTBaseServlet.class.getName());
    
    static DateTimeFormatter httpDateFormat = 
           DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss O", Locale.US);

    static int X_Request_ID = 1536;

    static final String OPEN_BANKING_HOST = "https://psd2.api.swedbank.com";

    static final SimpleDateFormat dateOnly = new SimpleDateFormat("yyyy-MM-dd");

    OpenBankingSessionData getObsd(HttpServletRequest request, 
                                   HttpServletResponse response) throws IOException {
        HttpSession session = request.getSession(false);
        if (session == null) {
            response.sendRedirect("home");
            return null;
        }
        return (OpenBankingSessionData)session.getAttribute(OBSD);
    }

    JSONObjectWriter createAccountConsent(JSONArrayReader jsonArrayReader) throws IOException {
        JSONObjectWriter consentData = new JSONObjectWriter();
        JSONArrayWriter accountEntry = new JSONArrayWriter();
        if (jsonArrayReader != null) {
            while (jsonArrayReader.hasMore()) {
                JSONObjectReader account = jsonArrayReader.getObject();
                accountEntry.setObject().setString("iban", account.getString("iban"));
            }
        }
        consentData.setObject("access")
            .setDynamic((wr) -> jsonArrayReader == null ?
                    wr.setString("availableAccounts", "allAccounts") :
                    wr.setArray("balances", accountEntry)
                      .setArray("accounts", accountEntry));
        consentData.setBoolean("combinedServiceIndicator", false) 
                   .setInt("frequencyPerDay", 0)
                   .setBoolean("recurringIndicator", false)
                   .setString("validUntil",  
            dateOnly.format(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 48))); 
        return consentData;
    }

    HTTPSWrapper getHTTPSWrapper() throws IOException {
        HTTPSWrapper wrapper = new HTTPSWrapper();
        wrapper.setHeader("Date", httpDateFormat.format(ZonedDateTime.now(ZoneOffset.UTC)));
        return wrapper;
    }
    
    void checkResponseCode(HTTPSWrapper wrapper,
                           int expectedResponseCode) throws IOException {
        int responseCode = wrapper.getResponseCode();
        if (responseCode != expectedResponseCode) {
            throw new IOException("Unexpected response code: " + 
                                  responseCode + 
                                  (responseCode < 500 ? "\ndata:" + wrapper.getDataUTF8() : ""));
        }
    }
    
    String getLocation(HTTPSWrapper wrapper) throws IOException {
        checkResponseCode(wrapper, HttpServletResponse.SC_FOUND);
        String location = wrapper.getHeaderValue("Location");
        if (location == null) {
            throw new IOException("\"Location\" is missing");
        }
        if (LocalIntegrationService.logging) {
            logger.info("Location: " + location);
        }
        return location;
    }
    
    JSONObjectReader getJsonData(HTTPSWrapper wrapper,
                                 int expectedResponseCode) throws IOException {
        checkResponseCode(wrapper, expectedResponseCode);
        String contentType = wrapper.getContentType();
        if (!contentType.equals(BaseProperties.JSON_CONTENT_TYPE)) {
            throw new IOException("Unexpected contentType: " + contentType);
        }
        JSONObjectReader json = JSONParser.parse(wrapper.getData());
        if (LocalIntegrationService.logging) {
            logger.info("Read JSON:\n" + json.toString());
        }
        return json;
    }

    JSONObjectReader getJsonData(HTTPSWrapper wrapper) throws IOException {
        return getJsonData(wrapper, HttpServletResponse.SC_OK);
    }

    static class RESTUrl {

        StringBuilder url;
        boolean next;
        
        RESTUrl(String baseUrl) {
            url = new StringBuilder(baseUrl);
        }
        
        RESTUrl addParameter(String name, String value) throws IOException {
            url.append(next ? '&' : '?')
               .append(name)
               .append('=')
               .append(URLEncoder.encode(value, "utf-8"));
            next = true;
            return this;
        }
        
        RESTUrl setBic() throws IOException {
            return addParameter("bic", "SANDSESS");
        }

        RESTUrl setAppId() throws IOException {
            return addParameter("app-id", LocalIntegrationService.oauth2ClientId);
        }

        @Override
        public String toString() {
            return url.toString();
        }
    }

    static class FormData {

        StringBuilder formData = new StringBuilder();
        boolean next;
             
        FormData addElement(String name, String value) throws IOException {
            if (next) {
                formData.append('&');
            }
            formData.append(name)
                    .append('=')
                    .append(URLEncoder.encode(value, "utf-8"));
            next = true;
            return this;
        }
        
        public byte[] toByteArray() throws IOException {
            return formData.toString().getBytes("utf-8");
        }
    }
    
    void setAuthorization(HTTPSWrapper wrapper,
                          OpenBankingSessionData obsd) throws IOException {
        wrapper.setHeader(HTTP_HEADER_AUTHORIZATION, "Bearer " + obsd.oauth2Token);
    }

    JSONObjectReader postJson(RESTUrl restUrl,
                              HTTPSWrapper wrapper,
                              JSONObjectWriter jsonRequestData,
                              int expectedResponseCode) throws IOException {
        if (LocalIntegrationService.logging) {
            logger.info("JSON to be POSTed (" + restUrl + ")\n" + jsonRequestData.toString());
        }
        wrapper.setHeader(HttpSupport.HTTP_CONTENT_TYPE_HEADER, BaseProperties.JSON_CONTENT_TYPE);
        wrapper.makePostRequest(restUrl.toString(), 
                                jsonRequestData.serializeToBytes(JSONOutputFormats.NORMALIZED));
        return getJsonData(wrapper, expectedResponseCode);
    }

    String getConsent(JSONArrayReader accountData, 
                      OpenBankingSessionData obsd, 
                      String successUrl) throws IOException {
        RESTUrl restUrl = new RESTUrl(OPEN_BANKING_HOST + "/sandbox/v2/consents")
            .setBic()
            .setAppId();
        HTTPSWrapper wrapper = getHTTPSWrapper();
        wrapper.setHeader(HTTP_HEADER_PSU_IP_ADDRESS, obsd.clientIpAddress);
        wrapper.setHeader(HTTP_HEADER_PSU_IP_PORT, "8442");
        wrapper.setHeader(HTTP_HEADER_PSU_HTTP_METHOD, "GET");
        wrapper.setHeader(HTTP_HEADER_PSU_USER_AGENT, obsd.userAgent);
        wrapper.setHeader(HTTP_HEADER_TTP_REDIRECT_URI,
                LocalIntegrationService.baseUri + successUrl);
        wrapper.setHeader(HTTP_HEADER_TPP_NOK_REDIRECT_URI, 
                LocalIntegrationService.baseUri + SCA_FAILED_PATH);
        setRequestId(wrapper);
        setAuthorization(wrapper, obsd);
        JSONObjectReader json = postJson(restUrl, 
                                         wrapper, 
                                         createAccountConsent(accountData), 
                                         HttpServletResponse.SC_CREATED);
        obsd.consentId = json.getString("consentId");
        String consentStatus = json.getString("consentStatus");
        if (consentStatus.equals("valid")) {
             return null;
        } else {
            if (accountData == null) {
                throw new IOException("Unexpeded \"consentStatus\": " + consentStatus);
            }
            JSONObjectReader links = json.getObject("_links");
            obsd.scaStatusUrl = OPEN_BANKING_HOST + links.getObject("scaStatus").getString("href");
            obsd.consentStatusUrl = OPEN_BANKING_HOST + links.getObject("status").getString("href");
            return links.getObject("scaRedirect").getString("href");
        }
    }

    JSONObjectReader performGet(HTTPSWrapper wrapper, RESTUrl restUrl) throws IOException {
        if (LocalIntegrationService.logging) {
            logger.info("About to GET: " + restUrl.toString());
        }
        wrapper.makeGetRequest(restUrl.toString());
        return getJsonData(wrapper);        
    }

    JSONObjectReader getAccountData(boolean withBalance,
                                    OpenBankingSessionData obsd) throws IOException {
        RESTUrl restUrl = new RESTUrl(OPEN_BANKING_HOST + "/sandbox/v2/accounts")
            .setBic()
            .addParameter("withBalance", String.valueOf(withBalance))
            .setAppId();
        HTTPSWrapper wrapper = getHTTPSWrapper();
        setRequestId(wrapper);
        setConsentId(wrapper, obsd);
        setAuthorization(wrapper, obsd);
        return performGet(wrapper, restUrl);
    }
    
    void setConsentId(HTTPSWrapper wrapper,
                      OpenBankingSessionData obsd) throws IOException {
        wrapper.setHeader(HTTP_HEADER_CONSENT_ID, obsd.consentId);
    }
    
    void setRequestId(HTTPSWrapper wrapper) throws IOException {
        wrapper.setHeader(HTTP_HEADER_X_REQUEST_ID, String.valueOf(X_Request_ID++));
    }

    void verifyOkStatus(boolean scaFlag, OpenBankingSessionData obsd) throws IOException {
        HTTPSWrapper scaStatus = getHTTPSWrapper();
        setRequestId(scaStatus);
        setConsentId(scaStatus, obsd);
        setAuthorization(scaStatus, obsd);
        RESTUrl restUrl = new RESTUrl(scaFlag ? obsd.scaStatusUrl : obsd.consentStatusUrl)
            .setBic()
            .setAppId();
        if (!performGet(scaStatus, restUrl)
                .getString(scaFlag ? "scaStatus" : "consentStatus")
                    .equals(scaFlag ? "finalised" : "valid")) {
            throw new IOException("Status error");
        }
    }
}
