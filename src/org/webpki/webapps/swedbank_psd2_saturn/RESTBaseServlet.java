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


abstract class RESTBaseServlet extends HttpServlet {
    
    private static final long serialVersionUID = 1L;
    
    static Logger logger = Logger.getLogger(RESTBaseServlet.class.getName());

    static final String PSD2_BASE_URL = "https://psd2.api.swedbank.com/psd2";

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

   
}
