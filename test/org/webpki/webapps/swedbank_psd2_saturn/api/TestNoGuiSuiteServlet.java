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

import java.math.BigDecimal;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.webapps.swedbank_psd2_saturn.HTML;

public class TestNoGuiSuiteServlet extends APICore {

    private static final long serialVersionUID = 1L;
    
    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
    throws IOException, ServletException {
        ////////////////////////////////////////////////////////////////////////////////
        // Before you can do anything you must be authenticated                       //
        // Note: this servlet is called by the browser from LIS                       //
        // The code below creates a session between LIS and the Open Banking service  //
        // for a specific user.  Note: Swedbank's Sandbox only supports a single user //
        // but we do this anyway to obtain consistency between implementations and be //
        // closer to a production version using an enhanced Open Banking API          //
        ////////////////////////////////////////////////////////////////////////////////
        OpenBankingSessionData obsd = 
                new OpenBankingSessionData(DEFAULT_USER,
                                           request.getRemoteAddr(),
                                           request.getHeader(HTTP_HEADER_USER_AGENT));
        if(!obsd.authorize()) {
            throw new IOException("Authorize");
        }
        ////////////////////////////////////////////////////////////////////////////////
        // We have the token, now get a plain account listing                         //
        ////////////////////////////////////////////////////////////////////////////////
        Accounts accounts = obsd.basicAccountList();

        ////////////////////////////////////////////////////////////////////////////////
        // We got an account list, now get balances for the found accounts            //
        ////////////////////////////////////////////////////////////////////////////////
        accounts = obsd.detailedAccountData(accounts.getAccountIds());
        
        String preSelected = null;
        BigDecimal highestAmount = BigDecimal.ZERO;
        for (String accountId : accounts.getAccountIds()) {
            Accounts.Account account = accounts.getAccount(accountId);
            // Pre-select the account with most money :)
            if (account.getBalance().compareTo(highestAmount) > 0) {
                highestAmount = account.getBalance();
                preSelected = accountId;
            }
        }
        
        ////////////////////////////////////////////////////////////////////////////////
        // Perform a payment operation                                                //
        ////////////////////////////////////////////////////////////////////////////////
  //      String paymentId = emulatedPaymentRequest();

        HTML.standardPage(response, 
            null,
            "<div class=\"header\">Test Suite GUI Less Operation</div>" +
            "<div class=\"centerbox\">" +
              "<div class=\"description\">Success!</i></div>" +
            "</div>");
        }

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
    throws IOException, ServletException {

        HTML.standardPage(response, 
            null,
            "<div class=\"header\">Test Suite GUI Less Operation</div>" +
            "<form name=\"guiless\" action=\"api.guiless\" method=\"POST\"></form>" +
            "<div class=\"centerbox\">" +
              "<div class=\"description\">Start a set of tests using the " +
               "&quot;emulated&quot; API.</div>" +
            "</div>" +
            "<div class=\"centerbox\">" +
              "<table>" +
                "<tr><td><div class=\"multibtn\" " +
                  "onclick=\"document.forms.guiless.submit()\" " +
                  "title=\"Run test suite\">" +
                  "Run...</div></td></tr>" +
              "</table>" +
            "</div>");
    }
}
