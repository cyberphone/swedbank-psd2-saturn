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
package org.webpki.webapps.swedbank_psd2_saturn;

import java.io.IOException;

import java.util.Enumeration;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.logging.Logger;

import org.webpki.json.JSONParser;

import org.webpki.saturn.common.BaseProperties;

import org.webpki.webutil.ServletUtil;

// Debug print

public class DebugServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    
    static Logger logger = Logger.getLogger(DebugServlet.class.getName());
    
    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        String query = request.getQueryString();
        logger.info("URL=" + request.getRequestURL().append(query == null ? "" : "?" + query).toString());
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String header = headerNames.nextElement();
            logger.info(header + ": " + request.getHeader(header));
        }
        if (request.getMethod().equals("POST")) {
            logger.info(JSONParser.parse(ServletUtil.getData(request)).toString());
        }
        response.setStatus(201);
        response.setContentType(BaseProperties.JSON_CONTENT_TYPE);
        byte[] json = "{\"debug\":true}".getBytes("utf-8");
        response.setContentLength(json.length);
        response.getOutputStream().write(json);
    }
    
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        doPost(request, response);
    }
}
