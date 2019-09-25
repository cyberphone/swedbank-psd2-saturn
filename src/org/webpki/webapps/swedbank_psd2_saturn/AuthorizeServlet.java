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
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.json.JSONObjectWriter;
import org.webpki.net.HTTPSWrapper;

public class AuthorizeServlet extends RESTBaseServlet {
/*
 *  https://psd2.api.swedbank.com:443/psd2/authorize?bic=SANDSESS&
 *  client_id=l77262db3b8475473b8b702c8ea4eaa136&
 *  response_type=code&scope=PSD2&redirect_uri=https%3A%2F%2F192.168.1.79%3A8442%2Fswedsand%2Facountauth
Res
 */
    private static final long serialVersionUID = 1L;
    
    static int X_Request_ID = 1536;
    
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            RESTUrl restUrl = new RESTUrl(PSD2_BASE_URL + "/authorize")
                .addParameter("bic", "SANDSESS")
                .addParameter("client_id", LocalPSD2Service.oauth2ClientId)
                .addParameter("response_type", "code")
                .addParameter("scope", "PSD2sandbox")
                .addParameter("redirect_uri", LocalPSD2Service.oauth2RedirectUri);
            if (LocalPSD2Service.logging) {
                logger.info(restUrl.toString());
            }
            HTTPSWrapper wrapper = new HTTPSWrapper();
            wrapper.setHeader("X-Request-ID", String.valueOf(X_Request_ID++));
            wrapper.setFollowRedirects(false);
            wrapper.makeGetRequest(restUrl.toString());
            if (wrapper.getResponseCode() != HttpServletResponse.SC_FOUND) {
                throw new IOException("FUCK");
            }
            String location = wrapper.getHeaderValue("Location");
            if (LocalPSD2Service.logging) {
                logger.info(location);
            }
            response.sendRedirect(location);
       } catch (Exception e) {
            
       }

        HTML.standardPage(response, null, new StringBuilder(
            "<div class=\"header\">Swedbank PSD2/Saturn API Demo</div>" +
            "<div style=\"padding-top:15pt\">This site permits testing a system using " +
            "Swedbanks's PSD2 API, running in an emulated local mode to support Saturn.  " +
            "For accessing the source code and documentation, click on the Saturn PSD2 logotype.</div>" +
            "<div style=\"display:flex;justify-content:center\"><table>" +
            "<tr><td><div class=\"multibtn\" " +
            "onclick=\"document.location.href='create'\" " +
            "title=\"Create Signed Request\">" +
            "Create Signed Request" +
            "</div></td></tr>" +
            "<tr><td><div class=\"multibtn\" " +
            "onclick=\"document.location.href='validate'\" " +
            "title=\"Validate Signed Request\">" +
            "Validate Signed Request" +
            "</div></td></tr>" +
            "<tr><td><div class=\"multibtn\" " +
            "onclick=\"document.location.href='curl'\" " +
            "title=\"Online Testing with CURL/Browser\">" +
            "Online Testing with CURL/Browser" +
            "</div></td></tr>" +
            "</table></div>" +
            "<div class=\"sitefooter\">This system only uses session cookies.</div>"));
    }
}
