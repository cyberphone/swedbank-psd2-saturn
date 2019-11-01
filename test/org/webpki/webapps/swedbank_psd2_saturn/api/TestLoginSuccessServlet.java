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

// This servlet is only called in the Test mode (using Open Banking GUI)

public class TestLoginSuccessServlet extends APICore {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
    throws IOException, ServletException {
        
        HTML.standardPage(response, null, new StringBuilder(
            HTML_HEADER +
            "<div class=\"centerbox\">" +
              "<div class=\"description\">Login Succeeded!</div>" +
            "</div>" +
            "<div class=\"centerbox\">" +
              "<table>" +
                "<tr><td><div class=\"multibtn\" " +
                "onclick=\"document.location.href = 'api.basicaccount'\" " +
                "title=\"Get Basic Account Data (no consent needed)\">" +
                "Step #2: Get Basic Account Data" +
                "</div></td></tr>" +
              "</table>" +
            "</div>"));
    }
}
