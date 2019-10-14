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

import org.webpki.webapps.swedbank_psd2_saturn.api.APICore;


public class HomeServlet extends APICore {

    private static final long serialVersionUID = 1L;
    
    public static final String SESSION_TIMEOUT = "timeout";
    
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {

        HTML.standardPage(response, null, new StringBuilder(
            "<div class=\"header\">Swedbank PSD2/Saturn API Demo</div>")
        .append(request.getParameter(SESSION_TIMEOUT) == null ? "" :
            "<div class=\"error\">Session Timed Out</div>")
        .append(
            "<div class=\"centerbox\">" +
              "<div class=\"description\">This site permits testing a system using " +
              "Swedbank's PSD2 API, running in an emulated local mode to support Saturn.  " +
              "For accessing the source code and documentation, click on the Saturn PSD2 logotype.</div>" +
            "</div>" +
            "<div class=\"centerbox\">" +
              "<table>" +
                "<tr><td><div class=\"multibtn\" " +
                "onclick=\"document.location.href='authorize'\" " +
                "title=\"Begin enrollment process\">" +
                "Begin Enrollment" +
                "</div></td></tr>" +
              "</table>" +
            "</div>" +
            "<div style=\"padding-top:15pt\"><a href=\"api.test\">Internal Testing Only</a></div>" +
            "<div class=\"sitefooter\">This system only uses session cookies.</div>"));
    }
}
