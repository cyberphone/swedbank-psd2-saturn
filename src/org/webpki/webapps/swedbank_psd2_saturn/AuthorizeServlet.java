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
import javax.servlet.http.HttpSession;

import org.webpki.net.HTTPSWrapper;

public class AuthorizeServlet extends RESTBaseServlet {

    private static final long serialVersionUID = 1L;
    
    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws IOException, ServletException {
        ////////////////////////////////////////////////////////////////////////////////
        // Before you can do anything you must be authenticated                       //
        // Note: this servlet is called by the browser from LIS                       //
        // The code below creates a session between LIS and the Open Banking service  //
        // for a specific user.  Note: Swedbank's Sandbox only supports a single user //
        // but we do this anyway to obtain consistency between implementations and be //
        // closer to a production version using an enhanced Open Banking API          //
        ////////////////////////////////////////////////////////////////////////////////
        HttpSession session = request.getSession();
        OpenBankingSessionData obsd = new OpenBankingSessionData();
        obsd.userAgent = request.getHeader(HTTP_HEADER_USER_AGENT);
        obsd.clientIpAddress = request.getRemoteAddr();
        session.setAttribute(OBSD, obsd);

        ////////////////////////////////////////////////////////////////////////////////
        // Initial LIS to API session creation.                                       //
        ////////////////////////////////////////////////////////////////////////////////
        String location = initializeApi();

        ////////////////////////////////////////////////////////////////////////////////
        // The returned "Location" is now returned to the browser as a redirect which //
        // in turn is supposed to invoke a Web authentication UI which if successful  //
        // should redirect back to the "redirect_uri" with an authentication code     //
        ////////////////////////////////////////////////////////////////////////////////
        if (LocalIntegrationService.emulationMode) {
            HTTPSWrapper wrapper = getBrowserEmulator(obsd);
            wrapper.makeGetRequest(location);
            Scraper scraper = new Scraper(wrapper);
            scraper.scanTo("<form ");
            RESTUrl restUrl = new RESTUrl(location, scraper.findWithin("action"))
                .addScrapedNameValue(scraper, "sessionID")
                .addScrapedNameValue(scraper, "sessionData")
                .addScrapedNameValue(scraper, "bic")
                .addParameter("userId", "55");
            logger.info(restUrl.toString());
            String cookie = wrapper.getHeaderValue("set-cookie");
            cookie = cookie.substring(0, cookie.indexOf(';'));

            wrapper = getBrowserEmulator(obsd);
            wrapper.setHeader("cookie", cookie);
            location = restUrl.toString();
            wrapper.makeGetRequest(location);
            scraper = new Scraper(wrapper);
            scraper.scanTo("<form ");
            restUrl = new RESTUrl(location, scraper.findWithin("action"))
                .addScrapedNameValue(scraper, "sessionID")
                .addScrapedNameValue(scraper, "sessionData")
                .addScrapedNameValue(scraper, "bic");
            logger.info(restUrl.toString());
        } else {
            response.sendRedirect(location);
        }
    }
}
