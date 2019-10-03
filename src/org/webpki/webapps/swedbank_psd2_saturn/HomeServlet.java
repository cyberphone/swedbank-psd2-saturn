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


public class HomeServlet extends RESTBaseServlet {

    private static final long serialVersionUID = 1L;
    
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {

        HTML.standardPage(response, null, new StringBuilder(
            "<div class=\"header\">Swedbank PSD2/Saturn API Demo</div>" +
            "<div style=\"padding-top:15pt\">This site permits testing a system using " +
            "Swedbanks's PSD2 API, running in an emulated local mode to support Saturn.  " +
            "For accessing the source code and documentation, click on the Saturn PSD2 logotype.</div>" +
            "<form name=\"authorize\" action=\"authorize\" method=\"POST\"></form>" +
            "<div style=\"display:flex;justify-content:center\"><table>" +
            "<tr><td><div class=\"multibtn\" " +
            "onclick=\"document.forms.authorize.submit()\" " +
            "title=\"Authorize\">" +
            "Login to Application" +
            "</div></td></tr>" +
/*
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
*/
            "</table></div>" +
            "<div class=\"sitefooter\">This system only uses session cookies.</div>"));
    }
}
