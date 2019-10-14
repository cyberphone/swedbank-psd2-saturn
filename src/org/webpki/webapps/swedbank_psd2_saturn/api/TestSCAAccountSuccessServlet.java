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
import org.webpki.webapps.swedbank_psd2_saturn.LocalIntegrationService;

public class TestSCAAccountSuccessServlet extends APICore {
    
    private static final long serialVersionUID = 1L;
    
    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws IOException, ServletException {
        ////////////////////////////////////////////////////////////////////////////////
        // Successful return after SCA (a dummy in the Sandbox)                       //
        ////////////////////////////////////////////////////////////////////////////////
        if (LocalIntegrationService.logging) {
            logger.info("Successful return after SCA");
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Check that we still have a session                                         //
        ////////////////////////////////////////////////////////////////////////////////
        OpenBankingSessionData obsd = getObsd(request, response);
        if (obsd == null) return;

        ////////////////////////////////////////////////////////////////////////////////
        // Verify that SCA is OK                                                      //
        ////////////////////////////////////////////////////////////////////////////////
        verifyOkStatus(true, obsd);
        
        ////////////////////////////////////////////////////////////////////////////////
        // Verify that Consent status is OK                                           //
        ////////////////////////////////////////////////////////////////////////////////
        verifyOkStatus(false, obsd);

        ////////////////////////////////////////////////////////////////////////////////
        // Now get rich account data (=with balances)                                 //
        ////////////////////////////////////////////////////////////////////////////////
        Accounts accounts = getAccountData(true, obsd);

        StringBuilder html = new StringBuilder(
                "<div class=\"header\">Internal API Test with GUI</div>" +
                "<div class=\"centerbox\">" +
                  "<table style=\"padding:15pt 0\">" +
                    "<tr><th>Account ID</th><th>Balance</th></tr>");
            for (String accountId : accounts.getAccountIds()) {
                Accounts.Account account = accounts.getAccount(accountId);
                html.append("<tr><td>")
                    .append(accountId)
                    .append("</td><td style=\"text-align:right\">")
                    .append(account.balance.toPlainString() + " " + account.getCurrency().toString())
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
