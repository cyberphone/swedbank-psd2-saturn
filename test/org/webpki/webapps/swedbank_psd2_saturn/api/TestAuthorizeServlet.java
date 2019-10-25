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
import javax.servlet.http.HttpSession;

import org.webpki.webapps.swedbank_psd2_saturn.HTML;

// This servlet MUST only called in the Test mode (using Open Banking GUI)
// and before any other Test mode servlets

public class TestAuthorizeServlet extends APICore {

    private static final long serialVersionUID = 1L;
    
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        
        HTML.standardPage(response, null, new StringBuilder(
            HTML_HEADER +
            "<div class=\"centerbox\">" +
              "<div class=\"description\">Note that the \"sandbox\" " +
              "login is a dummy, you can respond with anything.</div>" +
            "</div>" +
            "<form name=\"authorize\" action=\"api.test\" method=\"POST\"></form>" +
            "<div class=\"centerbox\">" +
              "<table>" +
                "<tr><td><div class=\"multibtn\" " +
                "onclick=\"document.forms.authorize.submit()\" " +
                "title=\"Authorize Login\">" +
                "Step #1: Authorize/Login" +
                "</div></td></tr>" +
              "</table>" +
            "</div>"));
    }

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
        HttpSession session = request.getSession();
        OpenBanking openBanking = new OpenBanking(DEFAULT_USER, request);
        session.setAttribute(OBSD, openBanking);

        ////////////////////////////////////////////////////////////////////////////////
        // Initial LIS to API session creation.                                       //
        ////////////////////////////////////////////////////////////////////////////////
        String location = initializeApi();

        ////////////////////////////////////////////////////////////////////////////////
        // The returned "Location" is now returned to the browser as a redirect which //
        // in turn is supposed to invoke a Web authentication UI which if successful  //
        // should redirect back to the "redirect_uri" with an authentication code     //
        ////////////////////////////////////////////////////////////////////////////////
        response.sendRedirect(location);
    }
}
