/*
 *  Copyright 2015-2020 WebPKI.org (http://webpki.org).
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

import java.math.BigDecimal;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.webapps.swedbank_psd2_saturn.HTML;
import org.webpki.webapps.swedbank_psd2_saturn.LocalIntegrationService;

public class TestConsentSuccessServlet extends APICore {
    
    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
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
        OpenBanking openBanking = getOpenBanking(request, response);
        if (openBanking == null) return;

        ////////////////////////////////////////////////////////////////////////////////
        // Now get rich account data (=with balances)                                 //
        ////////////////////////////////////////////////////////////////////////////////
        Accounts accounts = getAccountData(true, openBanking);

        StringBuilder html = new StringBuilder(
            HTML_HEADER +
            "<div class=\"centerbox\">" +
              "<div class=\"description\">Select source account for payment.</div>" +
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
            "function spawnPaymentSetup() {\n" +
            "  document.getElementById('" + 
               TestPaymentSetupServlet.ACCOUNT_ID_PARM + "').value = curr;\n" +
            "  document.forms.paymentSetup.submit();\n" +
            "}\n" +
            "window.addEventListener('load', (event) => {\n" +
            "  selectAccount(curr);\n" +
            "});\n",

            html.append(
              "</table>" +
            "</div>" +
            "<form name=\"paymentSetup\" action=\"api.paymentsetup\" method=\"POST\">" +
            "<input type=\"hidden\" id=\"" +
              TestPaymentSetupServlet.ACCOUNT_ID_PARM +
              "\" name=\"" +
              TestPaymentSetupServlet.ACCOUNT_ID_PARM +
              "\">" +
            "</form>" +
            "<div class=\"centerbox\">" +
              "<table>" +
                "<tr><td><div class=\"multibtn\" " +
                "onclick=\"spawnPaymentSetup()\" " +
                "title=\"Prepare for a payment operation\">" +
                "Step #5: Payment Operation Setup" +
                "</div></td></tr>" +
              "</table>" +
            "</div>"));
    }

    
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
        OpenBanking openBanking = getOpenBanking(request, response);
        if (openBanking == null) return;

        ////////////////////////////////////////////////////////////////////////////////
        // Verify that SCA is OK                                                      //
        ////////////////////////////////////////////////////////////////////////////////
        verifyScaStatus(openBanking);
        
        ////////////////////////////////////////////////////////////////////////////////
        // Verify that Consent status is OK                                           //
        ////////////////////////////////////////////////////////////////////////////////
        verifyConsentStatus(openBanking);

        HTML.standardPage(response, 
            null,
            HTML_HEADER +
            "<div class=\"centerbox\">" +
              "<div class=\"description\">Consent Succeeded.</div>" +
            "</div>" +
            "<div class=\"centerbox\">" +
              "<table>" +
                "<tr><td><div class=\"multibtn\" " +
                "onclick=\"document.location.href = 'api.consentsuccess'\" " +
                "title=\"Get more data for the accounts\">" +
                "Step #4: Get Extended Account Data" +
                "</div></td></tr>" +
              "</table>" +
            "</div>");
        }
}
