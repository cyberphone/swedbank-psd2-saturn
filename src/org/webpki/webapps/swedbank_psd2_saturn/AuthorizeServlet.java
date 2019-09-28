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

import org.webpki.net.HTTPSWrapper;

public class AuthorizeServlet extends RESTBaseServlet {

    private static final long serialVersionUID = 1L;
    
    public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws IOException, ServletException {
        ////////////////////////////////////////////////////////////////////////////////
        // Before you can do anything you must be authenticated                       //
        // Note: this servlet is called by the browser from LIS                       //
        // The code below only creates a session between LIS and the Open Banking     //
    	// service                                                                    //
        ////////////////////////////////////////////////////////////////////////////////
        RESTUrl restUrl = new RESTUrl(OPEN_BANKING_HOST + "/psd2/authorize")
            .setBic()
            .addParameter("client_id", LocalIntegrationService.oauth2ClientId)
            .addParameter("response_type", "code")
            .addParameter("scope", "PSD2sandbox")
            .addParameter("redirect_uri", LocalIntegrationService.oauth2RedirectUri);
        if (LocalIntegrationService.logging) {
            logger.info(restUrl.toString());
        }
        HTTPSWrapper wrapper = getHTTPSWrapper();
        wrapper.setHeader(HTTP_HEADER_X_REQUEST_ID, String.valueOf(X_Request_ID++));
        wrapper.makeGetRequest(restUrl.toString());
        String location = getLocation(wrapper);

        ////////////////////////////////////////////////////////////////////////////////
        // The returned "Location" is now returned to the browser as a redirect which //
        // in turn is supposed to invoke a Web authentication UI which if successful  //
        // should redirect back to the "redirect_uri" with an authentication code     //
        ////////////////////////////////////////////////////////////////////////////////
        response.sendRedirect(location);
    }
}
