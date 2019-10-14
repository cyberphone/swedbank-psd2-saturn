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

import org.webpki.webapps.swedbank_psd2_saturn.api.Accounts;
import org.webpki.webapps.swedbank_psd2_saturn.api.OpenBankingSessionData;
import org.webpki.webapps.swedbank_psd2_saturn.api.APICore;


public class AccountsServlet extends APICore {

    private static final long serialVersionUID = 1L;
    
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
    throws IOException, ServletException {

        ////////////////////////////////////////////////////////////////////////////////
        // Check that we still have a session                                         //
        ////////////////////////////////////////////////////////////////////////////////
        OpenBankingSessionData obsd = getObsd(request, response);
        if (obsd == null) return;

        ////////////////////////////////////////////////////////////////////////////////
        // We have the token, now get a plain account listing                         //
        ////////////////////////////////////////////////////////////////////////////////
        Accounts accounts = emulatedAccountDataAccess(null, obsd);

        ////////////////////////////////////////////////////////////////////////////////
        // We got an account list, now get balances for the found accounts            //
        ////////////////////////////////////////////////////////////////////////////////
        accounts = emulatedAccountDataAccess(accounts.getAccountIds(), obsd);

        StringBuilder html = new StringBuilder(
            "<div class=\"header\">Select Account</div>" +
            "<div class=\"centerbox\">" +
              "<div class=\"description\">Select an account to be used for payments.</div>" +
            "</div>" +
            "<div class=\"centerbox\">" +
              "<table class=\"tftable\">" +
                "<tr><th>Account ID</th><th>Balance</th></tr>");

        int i = 0;
        for (String accountId : accounts.getAccountIds()) {
            Accounts.Account account = accounts.getAccount(accountId);
            html.append("<tr id=\"")
                .append(i)
                .append("\" onclick=\"selectAccount('")
                .append(i)
                .append("')\"><td>")
                .append(accountId)
                .append("</td><td style=\"text-align:right\">")
                .append(account.getBalance().toPlainString() + " " + account.getCurrency().toString())
                .append("</td></tr>");
            i++;
        }
        
        HTML.standardPage(response,
            "var curr = '1';\n" +
            "function setColor(id, fg, bg) {\n" +
            "  var e = document.getElementById(id);\n" +
            "  e.style.color = fg;\n" +
            "  e.style.backgroundColor = bg;\n" +
            "}\n" +
            "function selectAccount(id) {\n" +
            "  setColor(curr, 'black', '#ffffe0');\n" +
            "  setColor(curr = id, 'white', '#5a7dff');\n" +
            "}\n" +
            "document.addEventListener('DOMContentLoaded', function() {\n" +
            "  selectAccount(curr);\n" +
            "});\n", 
            html.append(
              "</table>" +
            "</div>" +
            "<form name=\"accounts\" action=\"accounts\" method=\"POST\"></form>" +
            "<div class=\"centerbox\">" +
              "<table>" +
                "<tr><td><div class=\"multibtn\" " +
                  "onclick=\"document.forms.accounts.submit()\" " +
                  "title=\"Continue\">" +
                  "Continue...</div></td></tr>" +
              "</table>" +
            "</div>"));
    }
}
