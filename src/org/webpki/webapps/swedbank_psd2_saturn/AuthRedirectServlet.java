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

import org.webpki.net.HTTPSWrapper;

public class AuthRedirectServlet extends RESTBaseServlet {

    private static final long serialVersionUID = 1L;
    
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
        if (LocalPSD2Service.logging) {
            logger.info("code=" + code);
        }
        
        ////////////////////////////////////////////////////////////////////////////////
        // We got the code, now we need to upgrade it to a oauth2 token               //
        ////////////////////////////////////////////////////////////////////////////////
        FormData formData = new FormData()
            .addElement("grant_type", "authorization_code")
            .addElement("client_id", LocalPSD2Service.oauth2ClientId)
            .addElement("client_secret", LocalPSD2Service.oauth2ClientSecret)
            .addElement("code", code)
            .addElement("redirect_uri", LocalPSD2Service.oauth2RedirectUri);
        HTTPSWrapper wrapper = new HTTPSWrapper();
        wrapper.makePostRequest(PSD2_BASE_URL + "/token", formData.toByteArray());
        JSONObjectReader json = getJsonData(wrapper);
        oauth2Token = json.getString("access_token");
        if (LocalPSD2Service.logging) {
            logger.info("access_token=" + oauth2Token);
        }

        ////////////////////////////////////////////////////////////////////////////////
        // We got the token, now we need a consent for our accounts                   //
        ////////////////////////////////////////////////////////////////////////////////
        wrapper = new HTTPSWrapper();
        wrapper.setFollowRedirects(false);
        JSONObjectWriter requestJson = new JSONObjectWriter();
        response.sendRedirect("home");
    }
}
