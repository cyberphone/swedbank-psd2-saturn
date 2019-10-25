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

import java.math.BigDecimal;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.webapps.swedbank_psd2_saturn.api.Accounts;
import org.webpki.webapps.swedbank_psd2_saturn.api.OpenBanking;
import org.webpki.webapps.swedbank_psd2_saturn.api.APICore;

import org.webpki.webapps.swedbank_psd2_saturn.kg2.KeyProviderInitServlet;

public class AccountsServlet extends APICore {

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
        // We have the token, now get a plain account listing                         //
        ////////////////////////////////////////////////////////////////////////////////
        Accounts accounts = openBanking.basicAccountList();

        ////////////////////////////////////////////////////////////////////////////////
        // We got an account list, now get balances for the found accounts            //
        ////////////////////////////////////////////////////////////////////////////////
        accounts = openBanking.detailedAccountData(accounts.getAccountIds());

        StringBuilder html = new StringBuilder(
            "<div class=\"header\">Select Account</div>" +
            "<div class=\"centerbox\">" +
              "<div class=\"description\">Select account to be used for Saturn payments.</div>" +
            "</div>" +
            "<div class=\"centerbox\">" +
              "<table class=\"tftable\">" +
                "<tr><th>Account ID</th><th>Balance</th></tr>");

        String preSelected = null;
        BigDecimal highestAmount = BigDecimal.ZERO;
        for (String accountId : accounts.getAccountIds()) {
            Accounts.Account account = accounts.getAccount(accountId);
            // Pre-select the account with most money :)
            if (account.getBalance().compareTo(highestAmount) > 0) {
                highestAmount = account.getBalance();
                preSelected = accountId;
            }
            html.append("<tr style=\"cursor:pointer\" id=\"")
                .append(accountId)
                .append("\" onclick=\"selectAccount('")
                .append(accountId)
                .append("')\"><td>")
                .append(accountId)
                .append("</td><td style=\"text-align:right\">")
                .append(account.getBalance().toPlainString() + " " + account.getCurrency().toString())
                .append("</td></tr>");
        }
        
        HTML.standardPage(response,
            "var curr = '" + preSelected + "';\n" +
            "function setColor(id, fg, bg) {\n" +
            "  var e = document.getElementById(id);\n" +
            "  e.style.color = fg;\n" +
            "  e.style.backgroundColor = bg;\n" +
            "}\n" +
            "function selectAccount(id) {\n" +
            "  setColor(curr, 'black', '#ffffe0');\n" +
            "  setColor(curr = id, 'white', '#5a7dff');\n" +
            "}\n" +
            "function initiateEnrollment() {\n" +
            "  document.getElementById('" +
              KeyProviderInitServlet.ACCOUNT_SET_MODE_PARM +
              "').value = curr;\n" +
            "  document.forms.accountSelector.submit();\n" +
            "}\n" +
            "document.addEventListener('DOMContentLoaded', function() {\n" +
            "  selectAccount(curr);\n" +
            "});\n", 

            html.append(
              "</table>" +
            "</div>" +
            "<form name=\"accountSelector\" action=\"kg2.init\" method=\"POST\">" +
            "<input type=\"hidden\" id=\"" +
              KeyProviderInitServlet.ACCOUNT_SET_MODE_PARM +
              "\" name=\"" +
              KeyProviderInitServlet.ACCOUNT_SET_MODE_PARM +
              "\">" +
            "</form>" +
            "<div class=\"centerbox\">" +
              "<table>" +
                "<tr><td><div class=\"multibtn\" " +
                  "onclick=\"initiateEnrollment()\" " +
                  "title=\"Continue to enrollment\">" +
                  "Next...</div></td></tr>" +
              "</table>" +
            "</div>"));
    }
}
