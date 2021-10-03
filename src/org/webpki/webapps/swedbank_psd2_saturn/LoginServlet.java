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
package org.webpki.webapps.swedbank_psd2_saturn;

import java.io.IOException;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.webapps.swedbank_psd2_saturn.api.OpenBanking;

// The first servlet to call during an enrollment is authorize/login

public class LoginServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
    throws IOException, ServletException {
        ////////////////////////////////////////////////////////////////////////////////
        // Before you can do anything you must be authenticated                       //
        // Note: this servlet is called by the browser through the local service.     //
        // The code below creates a session between the local service and the         //
        // Open Banking service for a specific user.  Note: Swedbank's Sandbox only   //
        // supports a single user but we do this anyway to obtain consistency between //
        // implementations and be closer to a production version using an enhanced    //
        // Open Banking API                                                           //
        ////////////////////////////////////////////////////////////////////////////////
        
        ////////////////////////////////////////////////////////////////////////////////
        // After successful authorize/login we retrieve the user's accounts.          //
        ////////////////////////////////////////////////////////////////////////////////
        OpenBanking.createSession(request, response, "accounts");
    }

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
    throws IOException, ServletException {
        String userAgent = request.getHeader("User-Agent");
        boolean notOk = request.getParameter("override") == null;
        if (userAgent.contains("Android ")) {
            int i = userAgent.indexOf(" Chrome/");
            if (i > 0) {
                String chromeVersion = userAgent.substring(i + 8, userAgent.indexOf('.', i));
                if (Integer.parseInt(chromeVersion) >= SaturnDirectModeService.androidChromeVersion) {
                    notOk = false;
                }
            }
        }
        if (notOk) {
            HTML.standardPage(
                response,
                null,
                "<div class='label'>This proof-of-concept system only supports " +
                  "Android and using the \"Chrome\" browser (min version: " + 
                  SaturnDirectModeService.androidChromeVersion + ")" +
                "</div>");
            return;
        }

        HTML.standardPage(response, null, new StringBuilder(
            "<div class='header'>Login to Swedbank</div>" +
            "<form name='login' action='login' method='POST'></form>" +
            "<div class='centerbox'>" +
              "<div class='description'>The login in the Swedbank Open Banking " +
                "&quot;sandbox&quot; is rather primitive, respond with " +
                 "data like <b>12341234-1234</b> and proceed&nbsp;&#x1f642;</div>" +
            "</div>" +
            "<div class='centerbox'>" +
              "<table>" +
                "<tr><td><div class='multibtn' " +
                  "onclick=\"document.forms.login.submit()\" " +
                  "title='Login and retrieve account list'>" +
                  "Login...</div></td></tr>" +
              "</table>" +
            "</div>")
        .append(request.getParameter("demo") == null ?
            "<div class='centerbox' style='color:red;padding-top:1em'>" +
              "<div class='description'>Due to a bug in the Swedbank &quot;sandbox&quot; " +
              "you may be requested for certificates.  Ignore this request and click CANCEL!</div>" +
            "</div>" : ""));
    }
}
