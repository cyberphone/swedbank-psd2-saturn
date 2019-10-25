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

import org.webpki.webapps.swedbank_psd2_saturn.api.OpenBanking;
import org.webpki.webapps.swedbank_psd2_saturn.api.APICore;


public class AuthorizeServlet extends APICore {

    private static final long serialVersionUID = 1L;
    
    private static final String WAITING_ID = "wai";
    private static final String BUTTON_ID  = "btn";
    
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
        OpenBanking openBanking = new OpenBanking(DEFAULT_USER, request);
        if(openBanking.authorize()) {
            // We did it!  Continue to the next step but first
            // create an HTTP session (cookie) holding the precious OAuth2 token etc.
            request.getSession().setAttribute(OBSD, openBanking);
            response.sendRedirect("accounts");
        } else {
            doGet(request, response);
        }
    }

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
    throws IOException, ServletException {

        HTML.standardPage(response, 
            "function beginAuthorization() {\n" +
            "  document.getElementById('" + WAITING_ID + "').style.display = 'block';\n" +
            "  document.getElementById('" + BUTTON_ID + "').style.display = 'none';\n" +
            "  document.forms.authorize.submit();\n" +
            "}\n",
            "<div class=\"header\">Login to Application</div>" +
            "<form name=\"authorize\" action=\"authorize\" method=\"POST\"></form>" +
            "<div class=\"centerbox\">" +
              "<div class=\"description\">In a production setup you would need to login but " +
                "since the Swedbank Open Banking &quot;sandbox&quot; only supports a single " +
                "and unspecified user, <i>this step is just a dummy.</i></div>" +
            "</div>" +
            "<img id=\"" + WAITING_ID + 
              "\" src=\"images/waiting.gif\" style=\"padding-top:1em;display:none\">" +
            "<div id=\"" + BUTTON_ID + "\" class=\"centerbox\">" +
              "<table>" +
                "<tr><td><div class=\"multibtn\" " +
                  "onclick=\"beginAuthorization()\" " +
                  "title=\"Continue to account list\">" +
                  "Continue to Account List...</div></td></tr>" +
              "</table>" +
            "</div>");
    }
}
