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

import java.net.URLEncoder;

import java.util.logging.Logger;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletResponse;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONParser;

import org.webpki.net.HTTPSWrapper;

import org.webpki.saturn.common.BaseProperties;


abstract class RESTBaseServlet extends HttpServlet {
    
    private static final long serialVersionUID = 1L;
    
    static Logger logger = Logger.getLogger(RESTBaseServlet.class.getName());

    static String oauth2Token;
    
    static final String PSD2_BASE_URL = "https://psd2.api.swedbank.com/psd2";
    
    void checkResponseCode(HTTPSWrapper wrapper,
                           int expectedResponseCode) throws IOException {
        int responseCode = wrapper.getResponseCode();
        if (responseCode != expectedResponseCode) {
            throw new IOException("Unexpected response code: " + responseCode);
        }
    }
    
    String getLocation(HTTPSWrapper wrapper) throws IOException {
        checkResponseCode(wrapper, HttpServletResponse.SC_FOUND);
        String location = wrapper.getHeaderValue("Location");
        if (location == null) {
            throw new IOException("\"Location\" is missing");
        }
        if (LocalPSD2Service.logging) {
            logger.info("Location: " + location);
        }
        return location;
    }
    
    JSONObjectReader getJsonData(HTTPSWrapper wrapper,
                                 int expectedResponseCode) throws IOException {
        checkResponseCode(wrapper, expectedResponseCode);
        String contentType = wrapper.getContentType();
        if (!contentType.equals(BaseProperties.JSON_CONTENT_TYPE)) {
            throw new IOException("Unexpected contentType: " + contentType);
        }
        JSONObjectReader json = JSONParser.parse(wrapper.getData());
        if (LocalPSD2Service.logging) {
            logger.info(json.toString());
        }
        return json;
    }

    JSONObjectReader getJsonData(HTTPSWrapper wrapper) throws IOException {
        return getJsonData(wrapper, HttpServletResponse.SC_OK);
    }

    static class RESTUrl {

        StringBuilder url;
        boolean next;
        
        RESTUrl(String baseUrl) {
            url = new StringBuilder(baseUrl);
        }
        
        RESTUrl addParameter(String name, String value) throws IOException {
            url.append(next ? '&' : '?')
               .append(name)
               .append('=')
               .append(URLEncoder.encode(value, "utf-8"));
            next = true;
            return this;
        }
        
        @Override
        public String toString() {
            return url.toString();
        }
    }

    static class FormData {

        StringBuilder formData = new StringBuilder();
        boolean next;
             
        FormData addElement(String name, String value) throws IOException {
            if (next) {
                formData.append('&');
            }
            formData.append(name)
                    .append('=')
                    .append(URLEncoder.encode(value, "utf-8"));
            next = true;
            return this;
        }
        
        public byte[] toByteArray() throws IOException {
            return formData.toString().getBytes("utf-8");
        }
    }
}
