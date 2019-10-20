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

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.net.HTTPSWrapper;

import org.webpki.saturn.common.BaseProperties;
import org.webpki.saturn.common.HttpSupport;

import org.webpki.webapps.swedbank_psd2_saturn.HomeServlet;
import org.webpki.webapps.swedbank_psd2_saturn.LocalIntegrationService;

// This is the core API class.  It is both API and provider specific

public abstract class APICore extends HttpServlet {
    
    private static final long serialVersionUID = 1L;

    public static final String OBSD                      = "obsd";
    
    public static final String DEFAULT_USER              = "20010101-1234";
    
    public static final String HTTP_HEADER_USER_AGENT    = "User-Agent";
    
    static final String HTML_HEADER = "<div class=\"header\">Internal API Test with GUI</div>";


    // Possibly provider dependent
    static final String PRIMARY_ACCOUNT_TYPE             = "iban";

    static final String HTTP_HEADER_X_REQUEST_ID         = "X-Request-ID";
    static final String HTTP_HEADER_CONSENT_ID           = "Consent-ID";
    static final String HTTP_HEADER_AUTHORIZATION        = "Authorization";
    static final String HTTP_HEADER_PSU_IP_ADDRESS       = "PSU-IP-Address";
    static final String HTTP_HEADER_PSU_IP_PORT          = "PSU-IP-Port";
    static final String HTTP_HEADER_PSU_HTTP_METHOD      = "PSU-Http-Method";
    static final String HTTP_HEADER_PSU_USER_AGENT       = "PSU-User-Agent";
    static final String HTTP_HEADER_TTP_REDIRECT_URI     = "TPP-Redirect-URI";
    static final String HTTP_HEADER_TPP_NOK_REDIRECT_URI = "TPP-Nok-Redirect-URI";
    
    // Note: the following paths are only active in the Test (GUI) mode but
    // are anyway communicated in the emulated mode since they are required
    // by the Open Banking API
    static final String OAUTH2_REDIRECT_PATH             = "/api.authredirect";
    static final String SCA_ACCOUNT_SUCCESS_PATH         = "/api.scaaccountsuccess";
    static final String SCA_FAILED_PATH                  = "/api.scafailed";

    protected static Logger logger = Logger.getLogger(APICore.class.getName());
    
    static DateTimeFormatter httpDateFormat = 
           DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss O", Locale.US);

    static int X_Request_ID = 1536;

    static final String OPEN_BANKING_HOST = "https://psd2.api.swedbank.com";

    static final SimpleDateFormat dateOnly = new SimpleDateFormat("yyyy-MM-dd");

    static class Scraper {

        String html;
        int index;

        Scraper(HTTPSWrapper wrapper) throws IOException {
            if (!wrapper.getContentType().startsWith("text/html")) {
                throw new IOException("Unexpected content type: " + wrapper.getContentType());
            }
            html = wrapper.getDataUTF8();
            if (LocalIntegrationService.logging) {
 //               logger.info("Scraping html:\n" + html);
            }
        }
        
        void bad(String text) throws IOException {
            throw new IOException("Scraper: " + text);
        }

        Scraper scanTo(String tag) throws IOException {
            index = html.indexOf(tag, index);
            if (index++ < 0) bad(tag);
            return this;
        }
        
        String findWithin(String what) throws IOException {
            int last = html.indexOf('>', index);
            String sub = html.substring(index, last);
            int curr = sub.indexOf(" " + what + "=\"");
            if (curr < 0) bad(what);
            curr += what.length() + 3;
            last = sub.indexOf('"', curr);
            if (last < 0) bad(what);
            return sub.substring(curr, last);
        }

        public String inputNameValue(String name) throws IOException {
            scanTo("<input ");
            if (!findWithin("name").equals(name)) bad(name);
            return findWithin("value");
        }

        @Override
        public String toString() {
            return html;
        }
    }
    
    public static OpenBankingSessionData getObsd(HttpServletRequest request, 
                                                 HttpServletResponse response) 
    throws IOException {
        HttpSession session = request.getSession(false);
        if (session == null) {
            response.sendRedirect(HomeServlet.REDIRECT_TIMEOUT_URI);
            return null;
        }
        return (OpenBankingSessionData)session.getAttribute(OBSD);
    }

    static JSONObjectWriter createAccountConsent(String[] accountIds) throws IOException {
        JSONObjectWriter consentData = new JSONObjectWriter();
        JSONArrayWriter accountEntry = new JSONArrayWriter();
        if (accountIds != null) {
            for (String accountId : accountIds) {
                accountEntry.setObject().setString(PRIMARY_ACCOUNT_TYPE, accountId);
            }
        }
        consentData.setObject("access")
            .setDynamic((wr) -> accountIds == null ?
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

    static HTTPSWrapper getHTTPSWrapper() throws IOException {
        HTTPSWrapper wrapper = new HTTPSWrapper();
        wrapper.setHeader("Date", httpDateFormat.format(ZonedDateTime.now(ZoneOffset.UTC)));
        return wrapper;
    }
    
    static HTTPSWrapper getBrowserEmulator(OpenBankingSessionData obsd) throws IOException {
        HTTPSWrapper wrapper = getHTTPSWrapper();
        wrapper.setHeader(HTTP_HEADER_USER_AGENT, obsd.userAgent);
        return wrapper;
    }
    
    static void checkResponseCode(HTTPSWrapper wrapper,
                                  int expectedResponseCode) throws IOException {
        int responseCode = wrapper.getResponseCode();
        if (responseCode != expectedResponseCode) {
            throw new IOException("Unexpected response code: " + 
                                  responseCode + 
                                  (responseCode < 500 ? "\ndata:" + wrapper.getDataUTF8() : ""));
        }
    }
    
    static String getLocation(HTTPSWrapper wrapper) throws IOException {
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
    
    static JSONObjectReader getJsonData(HTTPSWrapper wrapper,
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

    static JSONObjectReader getJsonData(HTTPSWrapper wrapper) throws IOException {
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

        RESTUrl addScrapedNameValue(Scraper scraper, String name) throws IOException {
            return addParameter(name, scraper.inputNameValue(name));
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
        
        FormData addScrapedNameValue(Scraper scraper, String name) throws IOException {
            return addElement(name, scraper.inputNameValue(name));
        }

        public byte[] toByteArray() throws IOException {
            return formData.toString().getBytes("utf-8");
        }
    }
    
    static String combineUrl(String derivedUrl, String path) {
        if (path.startsWith("https:")) {
            return path;
        }
        if (path.startsWith("/")) {
            return derivedUrl.substring(0, derivedUrl.indexOf('/', 8)) + path;
        }
        int i = derivedUrl.indexOf('?');
        if (i > 0) {
            derivedUrl = derivedUrl.substring(0, i);
        }
        i = derivedUrl.lastIndexOf('/');
        return derivedUrl.substring(0, i + 1) + path;
    }

    static void getOAuth2Token(OpenBankingSessionData obsd, String code) throws IOException {
        FormData formData = new FormData()
            .addElement("grant_type", "authorization_code")
            .addElement("client_id", LocalIntegrationService.oauth2ClientId)
            .addElement("client_secret", LocalIntegrationService.oauth2ClientSecret)
            .addElement("code", code)
            .addElement("redirect_uri", LocalIntegrationService.bankBaseUri + OAUTH2_REDIRECT_PATH);
        HTTPSWrapper wrapper = getHTTPSWrapper();
        wrapper.makePostRequest(OPEN_BANKING_HOST + "/psd2/token", formData.toByteArray());
        obsd.oauth2Token = getJsonData(wrapper).getString("access_token");
    }

    static void setAuthorization(HTTPSWrapper wrapper,
                                 OpenBankingSessionData obsd) throws IOException {
        wrapper.setHeader(HTTP_HEADER_AUTHORIZATION, "Bearer " + obsd.oauth2Token);
    }

    static JSONObjectReader postJson(RESTUrl restUrl,
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

    static String getConsent(String[] accountIds, 
                             OpenBankingSessionData obsd) throws IOException {
        RESTUrl restUrl = new RESTUrl(OPEN_BANKING_HOST + "/sandbox/v2/consents")
            .setBic()
            .setAppId();
        HTTPSWrapper wrapper = getHTTPSWrapper();
        wrapper.setHeader(HTTP_HEADER_PSU_IP_ADDRESS, obsd.clientIpAddress);
        wrapper.setHeader(HTTP_HEADER_PSU_IP_PORT, "8442");
        wrapper.setHeader(HTTP_HEADER_PSU_HTTP_METHOD, "GET");
        wrapper.setHeader(HTTP_HEADER_PSU_USER_AGENT, obsd.userAgent);
        wrapper.setHeader(HTTP_HEADER_TTP_REDIRECT_URI,
                LocalIntegrationService.bankBaseUri + SCA_ACCOUNT_SUCCESS_PATH);
        wrapper.setHeader(HTTP_HEADER_TPP_NOK_REDIRECT_URI, 
                LocalIntegrationService.bankBaseUri + SCA_FAILED_PATH);
        setRequestId(wrapper);
        setAuthorization(wrapper, obsd);
        JSONObjectReader json = postJson(restUrl, 
                                         wrapper, 
                                         createAccountConsent(accountIds), 
                                         HttpServletResponse.SC_CREATED);
        obsd.consentId = json.getString("consentId");
        String consentStatus = json.getString("consentStatus");
        if (accountIds == null ^ consentStatus.equals("valid")) {
            throw new IOException("Unexpeded \"consentStatus\": " + consentStatus);
        }
        if (accountIds == null) {
             return null;
        }
        JSONObjectReader links = json.getObject("_links");
        obsd.scaStatusUrl = OPEN_BANKING_HOST + links.getObject("scaStatus").getString("href");
        obsd.consentStatusUrl = OPEN_BANKING_HOST + links.getObject("status").getString("href");
        return links.getObject("scaRedirect").getString("href");
    }

    static JSONObjectReader performGet(HTTPSWrapper wrapper, RESTUrl restUrl) throws IOException {
        if (LocalIntegrationService.logging) {
            logger.info("About to GET: " + restUrl.toString());
        }
        wrapper.makeGetRequest(restUrl.toString());
        return getJsonData(wrapper);        
    }

    static Accounts getAccountData(boolean withBalance,
                                   OpenBankingSessionData obsd) throws IOException {
        obsd.consistencyCheck(withBalance);
        RESTUrl restUrl = new RESTUrl(OPEN_BANKING_HOST + "/sandbox/v2/accounts")
            .setBic()
            .addParameter("withBalance", String.valueOf(withBalance))
            .setAppId();
        HTTPSWrapper wrapper = getHTTPSWrapper();
        setRequestId(wrapper);
        setConsentId(wrapper, obsd);
        setAuthorization(wrapper, obsd);
        obsd.accountData = performGet(wrapper, restUrl);
        return new Accounts(obsd.accountData);
    }
    
    static void setConsentId(HTTPSWrapper wrapper,
                             OpenBankingSessionData obsd) throws IOException {
        wrapper.setHeader(HTTP_HEADER_CONSENT_ID, obsd.consentId);
    }
    
    static void setRequestId(HTTPSWrapper wrapper) throws IOException {
        wrapper.setHeader(HTTP_HEADER_X_REQUEST_ID, String.valueOf(X_Request_ID++));
    }

    static void verifyOkStatus(boolean scaFlag, OpenBankingSessionData obsd) throws IOException {
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

    static String initializeApi() throws IOException {
        RESTUrl restUrl = new RESTUrl(OPEN_BANKING_HOST + "/psd2/authorize")
            .setBic()
            .addParameter("client_id", LocalIntegrationService.oauth2ClientId)
            .addParameter("response_type", "code")
            .addParameter("scope", "PSD2sandbox")
            .addParameter("redirect_uri",
                          LocalIntegrationService.bankBaseUri + OAUTH2_REDIRECT_PATH);
        HTTPSWrapper wrapper = getHTTPSWrapper();
        setRequestId(wrapper);
        if (LocalIntegrationService.logging) {
            logger.info("About to GET: " + restUrl.toString());
        }
        wrapper.makeGetRequest(restUrl.toString());
        return getLocation(wrapper);
    }
    
    public static boolean emulatedAuthorize(OpenBankingSessionData obsd) throws IOException {
        ////////////////////////////////////////////////////////////////////////////////
        // Initial LIS to API session creation.                                       //
        ////////////////////////////////////////////////////////////////////////////////
        String location = initializeApi();

        ////////////////////////////////////////////////////////////////////////////////
        // The returned "Location" is now returned to the browser as a redirect which //
        // in turn is supposed to invoke a Web authentication UI which if successful  //
        // should redirect back to the "redirect_uri" with an authentication code.    //
        //                                                                            //
        // Now, this isn't actually true because the code below does "Web Scraping"   //
        // in a VERY provider specific way.                                           //                            
        ////////////////////////////////////////////////////////////////////////////////
        HTTPSWrapper wrapper = getBrowserEmulator(obsd);
        wrapper.makeGetRequest(location);
        Scraper scraper = new Scraper(wrapper);
        scraper.scanTo("<form ");
        RESTUrl restUrl = new RESTUrl(combineUrl(location, scraper.findWithin("action")))
            .addScrapedNameValue(scraper, "sessionID")
            .addScrapedNameValue(scraper, "sessionData")
            .addScrapedNameValue(scraper, "bic")
            .addParameter("userId", obsd.userId);
        location = restUrl.toString();
        String setCookie = wrapper.getHeaderValue("set-cookie");
        obsd.emulatorModeCookie = setCookie.substring(0, setCookie.indexOf(';'));
 
        wrapper = getBrowserEmulator(obsd);
        wrapper.setHeader("cookie", obsd.emulatorModeCookie);
        logger.info(location);
        wrapper.makeGetRequest(location);
        scraper = new Scraper(wrapper);
        scraper.scanTo("<form ");
        restUrl = new RESTUrl(combineUrl(location, scraper.findWithin("action")))
            .addScrapedNameValue(scraper, "sessionID")
            .addScrapedNameValue(scraper, "sessionData")
            .addScrapedNameValue(scraper, "bic");
        location = restUrl.toString();

        wrapper = getBrowserEmulator(obsd);
        wrapper.setHeader("cookie", obsd.emulatorModeCookie);
        logger.info(location);
        wrapper.makeGetRequest(location);
        logger.info(String.valueOf(wrapper.getResponseCode()));
        scraper = new Scraper(wrapper);
        scraper.scanTo("<form ");
        location = combineUrl(location, scraper.findWithin("action"));
        FormData formData = new FormData()
            .addScrapedNameValue(scraper, "sessionID")
            .addScrapedNameValue(scraper, "sessionData")
            .addScrapedNameValue(scraper, "action")
            .addScrapedNameValue(scraper, "bic");

        wrapper = getBrowserEmulator(obsd);
        wrapper.setHeader("cookie", obsd.emulatorModeCookie);
        logger.info(location);
        wrapper.makePostRequest(location, formData.toByteArray());
        location = getLocation(wrapper);

        ////////////////////////////////////////////////////////////////////////////////
        // We should now have the "code" parameter                                    //
        ////////////////////////////////////////////////////////////////////////////////
        int i = location.indexOf("?code=");
        if (i < 0) {
            throw new IOException("Didn't find 'code' object");
        }
        String code = location.substring(i + 6);
        if (LocalIntegrationService.logging) {
            logger.info("code=" + code);
        }

        ////////////////////////////////////////////////////////////////////////////////
        // We got the code, now we need to upgrade it to an oauth2 token              //
        ////////////////////////////////////////////////////////////////////////////////
        getOAuth2Token(obsd, code);
        
        ////////////////////////////////////////////////////////////////////////////////
        // Since this is an emulator supporting a single user we always succeed :-)   //
        ////////////////////////////////////////////////////////////////////////////////
        return true;
    }
    
    public static Accounts emulatedAccountDataAccess(String[] accountIds,
                                                     OpenBankingSessionData obsd)
    throws IOException {
        String location = getConsent(accountIds, obsd);
        if (location == null) {
            return getAccountData(false, obsd);
        }
        HTTPSWrapper wrapper = getBrowserEmulator(obsd);
        wrapper.makeGetRequest(location);
        Scraper scraper = new Scraper(wrapper);
        String setCookie = wrapper.getHeaderValue("set-cookie");
        obsd.emulatorModeCookie = setCookie.substring(0, setCookie.indexOf(';'));
        scraper.scanTo("<form ").scanTo("<form ");
        location = combineUrl(location, scraper.findWithin("action"));
        FormData formData = new FormData()
            .addScrapedNameValue(scraper, "token")
            .addScrapedNameValue(scraper, "bic")
            .addScrapedNameValue(scraper, "action");

        wrapper = getBrowserEmulator(obsd);
        wrapper.setHeader("cookie", obsd.emulatorModeCookie);
        logger.info(location);
        wrapper.makePostRequest(location, formData.toByteArray());
        scraper = new Scraper(wrapper);
        if (!scraper.scanTo("<form ").findWithin("action").endsWith(SCA_ACCOUNT_SUCCESS_PATH)) {
            throw new IOException("Internal error, consent did not succeed");
        }
        return getAccountData(true, obsd);
    }
}
