/*
 *  Copyright 2015-2019 WebPKI.org (http://webpki.org).
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

import org.webpki.json.JSONObjectWriter;

import org.webpki.saturn.common.Currencies;

import org.webpki.webapps.swedbank_psd2_saturn.HTML;
import org.webpki.webapps.swedbank_psd2_saturn.LocalIntegrationService;

// This servlet is only called in the Test mode (using Open Banking GUI)

public class TestPaymentSetupServlet extends APICore {

    private static final long serialVersionUID = 1L;

    static final String FIXED_CREDITOR_ACCOUNT = "BG 5051-6905";
    static final String FIXED_CREDITOR_NAME    = "Demo Merchant";
    static final Currencies FIXED_CURRENCY     = Currencies.SEK;
    static final BigDecimal FIXED_AMOUNT       = new BigDecimal("100.00");
    static long reference                      = 1000007;
    
    static final String ACCOUNT_ID_PARM        = "account";
    static final String PAYMENT_MESSAGE_ATTR   = "payment";
    
    String tableEntry(String name, String value) {
        return "<tr><td style=\"text-align:right;font-weight:bold\">" +
               name + "</td><td>" + value + "</td></tr>";
    }
    
    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
    throws IOException, ServletException {

        ////////////////////////////////////////////////////////////////////////////////
        // Check that we still have a session                                         //
        ////////////////////////////////////////////////////////////////////////////////
        OpenBanking openBanking = getOpenBanking(request, response);
        if (openBanking == null) return;

        ////////////////////////////////////////////////////////////////////////////////
        // Get selected account                                                       //
        ////////////////////////////////////////////////////////////////////////////////
        String selectedAccount = request.getParameter(ACCOUNT_ID_PARM);
        if (selectedAccount == null) {
            throw new IOException("Account missing");
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Create payment JSON and save it in the session                             //
        ////////////////////////////////////////////////////////////////////////////////
        String refString = String.format("%010d", ++reference);
        request.getSession(false)
            .setAttribute(PAYMENT_MESSAGE_ATTR, 
                          createPaymentMessage(selectedAccount, 
                                               FIXED_CREDITOR_ACCOUNT,
                                               FIXED_AMOUNT,
                                               FIXED_CURRENCY,
                                               FIXED_CREDITOR_NAME,
                                               refString));
        HTML.standardPage(response, null, new StringBuilder(
            HTML_HEADER +
            "<div class=\"centerbox\">" +
              "<div class=\"description\">Payment operation to be performed.</div>" +
            "</div>" +
            "<div class=\"centerbox\">" +
              "<table class=\"tftable\">")
            .append(tableEntry("Creditor Name", FIXED_CREDITOR_NAME))
            .append(tableEntry("Reference", refString))
            .append(tableEntry("Creditor Account (Fixed)", FIXED_CREDITOR_ACCOUNT))
            .append(tableEntry("Selected Debtor Account", selectedAccount))
            .append(tableEntry("Amount (Fixed)", 
                FIXED_AMOUNT.toPlainString() + " " + FIXED_CURRENCY.toString()))
            .append(
              "</table>" +
            "</div>" +
            "<div class=\"centerbox\">" +
              "<table>" +
                "<tr><td><div class=\"multibtn\" " +
                "onclick=\"document.location.href = 'api.paymentsetup'\" " +
                "title=\"Perform payment\">" +
                "Step #6: Perform Payment" +
                "</div></td></tr>" +
              "</table>" +
            "</div>"));
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response)
    throws IOException, ServletException {

        ////////////////////////////////////////////////////////////////////////////////
        // Check that we still have a session                                         //
        ////////////////////////////////////////////////////////////////////////////////
        OpenBanking openBanking = getOpenBanking(request, response);
        if (openBanking == null) return;

        ////////////////////////////////////////////////////////////////////////////////
        // Get payment message                                       //
        ////////////////////////////////////////////////////////////////////////////////
        JSONObjectWriter paymentMessage = 
                (JSONObjectWriter) request.getSession(false).getAttribute(PAYMENT_MESSAGE_ATTR);
        if (LocalIntegrationService.logging) {
            logger.info(paymentMessage.toString());
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Now perform payment which should require SCA                               //
        ////////////////////////////////////////////////////////////////////////////////
        String scaRedirectUrl = initiatePayment(openBanking, paymentMessage);
        if (LocalIntegrationService.logging) {
            logger.info("Redirect to:\n" + scaRedirectUrl);
        }
        response.sendRedirect(scaRedirectUrl);
    }
}
