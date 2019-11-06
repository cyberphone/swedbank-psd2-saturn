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

import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.webapps.swedbank_psd2_saturn.LocalIntegrationService;

// This servlet is only called in the Test mode (using Open Banking GUI)

public class TestExtendedAccountServlet extends APICore {

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
        // We should by now have an existing basic account listing                    //
        ////////////////////////////////////////////////////////////////////////////////
        Accounts accounts = new Accounts(openBanking);

        ////////////////////////////////////////////////////////////////////////////////
        // Now get more details.  For that we need a consent                          //
        ////////////////////////////////////////////////////////////////////////////////
        String scaRedirectUrl = getConsent(accounts.getAccountIds(), openBanking);
        if (LocalIntegrationService.logging) {
            logger.info("Redirect to:\n" + scaRedirectUrl);
        }
        response.sendRedirect(scaRedirectUrl);
    }
}
