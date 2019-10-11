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

import org.webpki.webapps.swedbank_psd2_saturn.api.OpenBankingSessionData;
import org.webpki.webapps.swedbank_psd2_saturn.api.APICore;


public class AccountsServlet extends APICore {

    private static final long serialVersionUID = 1L;
    
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {

        HTML.standardPage(response, null, new StringBuilder(
            "<div class=\"header\">Select Account</div>" +
            "<form name=\"authorize\" action=\"authorize\" method=\"POST\"></form>" +
            "<div class=\"centerbox\">" +
              "<div style=\"padding-top:15pt\">In a production setup you would need to login but " +
                "since the Swedbank Open Banking &quot;sandbox&quot; only supports a single user, " +
                "this step is just a dummy.</div>" +
            "</div>" +
            "<div class=\"centerbox\">" +
              "<table>" +
                "<tr><td><div class=\"multibtn\" " +
                  "onclick=\"document.forms.authorize.submit()\" " +
                  "title=\"Continue to account list\">" +
                  "Continue...</div></td></tr>" +
              "</table>" +
            "</div>"));
    }
}
