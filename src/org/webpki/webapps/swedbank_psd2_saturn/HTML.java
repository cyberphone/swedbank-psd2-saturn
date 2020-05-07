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

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HTML {

    static Logger logger = Logger.getLogger(HTML.class.getName());

    static final String HTML_INIT = "<!DOCTYPE html>" +
        "<html lang=\"en\"><head><link rel=\"icon\" href=\"saturn.png\" sizes=\"192x192\">" + 
        "<meta name=\"viewport\" content=\"initial-scale=1.0\"/>" + 
        "<title>Swedbank Saturn/PSD2 Lab</title>" + 
        "<link rel=\"stylesheet\" type=\"text/css\" href=\"style.css\">";

    static String encode(String val) {
        if (val != null) {
            StringBuilder buf = new StringBuilder(val.length() + 8);
            char c;

            for (int i = 0; i < val.length(); i++) {
                c = val.charAt(i);
                switch (c) {
                case '<':
                    buf.append("&lt;");
                    break;
                case '>':
                    buf.append("&gt;");
                    break;
                case '&':
                    buf.append("&amp;");
                    break;
                case '\"':
                    buf.append("&#034;");
                    break;
                case '\'':
                    buf.append("&#039;");
                    break;
                default:
                    buf.append(c);
                    break;
                }
            }
            return buf.toString();
        } else {
            return new String("");
        }
    }

    public static String getHTML(String javascript, String box) {
        StringBuilder html = new StringBuilder(
            HTML_INIT + 
            "<script>\n\"use strict\";\n" +
            "history.pushState(null, null, 'home');\n" +
            "window.addEventListener('popstate', function(event) {\n" +
            "  history.pushState(null, null, 'home');\n" +
            "});\n");
        if (javascript != null) {
            html.append(javascript);
        }
        html.append(
            "</script></head><body>" +
            "<img src=\"images/thelab.svg\" " +
            "style=\"cursor:pointer;position:absolute;height:25pt;top:15pt;left:15pt\"" +
            " onclick=\"document.location.href='home'\" title=\"Home of the lab...\"/>" +
            "<a href=\"https://github.com/cyberphone/swedbank-psd2-saturn\" target=\"_blank\">" +
            "<img src=\"images/saturn-psd2.svg\" " +
            "style=\"position:absolute;height:30pt;top:14pt;right:15pt\" " +
            "title=\"Specifications, source code, etc.\"/></a>" +
            "<div class=\"displayContainer\">")
        .append(box).append("</div></body></html>");
        return html.toString();
    }

    public static void output(HttpServletResponse response, String html)
            throws IOException, ServletException {
//      logger.info("\n\n" + html + "\n\n");
        response.setContentType("text/html; charset=utf-8");
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "No-Cache");
        response.setDateHeader("EXPIRES", 0);
        response.getOutputStream().write(html.getBytes("utf-8"));
    }

    static String getConditionalParameter(HttpServletRequest request,
            String name) {
        String value = request.getParameter(name);
        if (value == null) {
            return "";
        }
        return value;
    }
    
    public static String boxHeader(String id, String text, boolean visible) {
        return new StringBuilder("<div id='")
            .append(id)
            .append("' style='padding-top:10pt")
            .append(visible ? "" : ";display:none")
            .append("'>" +
               "<div style='padding-bottom:3pt'>" + text + ":</div>").toString();
    }

    public static String fancyBox(String id, String content, String header) {
        return boxHeader(id, header, true) +
            "<div class='staticbox'>" + content + "</div></div>";
    }

    public static String fancyText(boolean visible,
                                   String id, 
                                   int rows, 
                                   String content,
                                   String header) {
        return boxHeader(id, header, visible) +
            "<textarea" +
            " rows='" + rows + "' maxlength='100000'" +
            " class='textbox' name='" + id + "'>" + 
            content +
            "</textarea></div>";
    }
    
    public static void standardPage(HttpServletResponse response, 
                                    String javaScript,
                                    StringBuilder htmlBuffer) throws IOException, ServletException {
        standardPage(response, javaScript, htmlBuffer.toString());
    }

    public static void standardPage(HttpServletResponse response, 
                                    String javaScript,
                                    String html) throws IOException, ServletException {
        HTML.output(response, HTML.getHTML(javaScript, html));
    }

    static String javaScript(String string) {
        StringBuilder html = new StringBuilder();
        for (char c : string.toCharArray()) {
            if (c == '\n') {
                html.append("\\n");
            } else {
                html.append(c);
            }
        }
        return html.toString();
    }

    public static void errorPage(HttpServletResponse response, Exception e)
            throws IOException, ServletException {
        standardPage(response,
                     null,
                     new StringBuilder(
            "<div class='header' style='color:red'>Something went wrong...</div>" +
            "<div><pre>")
 //       .append(encode(BaseRequestServlet.getStackTrace(e)))
        .append("</pre></div>"));
    }
}
