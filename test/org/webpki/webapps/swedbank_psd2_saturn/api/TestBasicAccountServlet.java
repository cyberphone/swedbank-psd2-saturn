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

import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.webapps.swedbank_psd2_saturn.HTML;

// This servlet is only called in the Test mode (using Open Banking GUI)

public class TestBasicAccountServlet extends APICore {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
    throws IOException, ServletException {

        ////////////////////////////////////////////////////////////////////////////////
        // Check that we still have a session                                         //
        ////////////////////////////////////////////////////////////////////////////////
        OpenBanking openBanking = getOpenBanking(request, response);
        if (openBanking == null) return;

        ////////////////////////////////////////////////////////////////////////////////
        // We have the token, now we need a consent for basic listing our accounts    //
        ////////////////////////////////////////////////////////////////////////////////
        getConsent(null, openBanking);

        ////////////////////////////////////////////////////////////////////////////////
        // We got the consent, now use it!                                            //
        ////////////////////////////////////////////////////////////////////////////////
        Accounts accounts = getAccountData(false, openBanking);
        
        StringBuilder html = new StringBuilder(
            HTML_HEADER +
            "<div class=\"centerbox\">" +
              "<div class=\"description\">Basic Account Information</div>" +
            "</div>" +
            "<div class=\"centerbox\">" +
              "<table class=\"tftable\"><tr><th>Account ID</th></tr>");
        for (String accountId : accounts.getAccountIds()) {
            html.append("<tr><td>")
                .append(accountId)
                .append("</td></tr>");
        }
        
        HTML.standardPage(response, null, html.append(
              "</table>" +
            "</div>" +
            "<div class=\"centerbox\">" +
              "<table>" +
                "<tr><td><div class=\"multibtn\" " +
                "onclick=\"document.location.href = 'api.extendedaccount'\" " +
                "title=\"Get extended account data (consent needed)\">" +
                "Step #3: Get Extended Account Data" +
                "</div></td></tr>" +
              "</table>" +
            "</div>"));
    }
}
