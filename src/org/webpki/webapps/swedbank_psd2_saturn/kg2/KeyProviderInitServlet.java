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

package org.webpki.webapps.swedbank_psd2_saturn.kg2;

import java.io.IOException;

import java.util.logging.Logger;

import java.net.URLEncoder;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.webpki.keygen2.ServerState;

import org.webpki.net.MobileProxyParameters;

import org.webpki.webapps.swedbank_psd2_saturn.HomeServlet;
import org.webpki.webapps.swedbank_psd2_saturn.HTML;
import org.webpki.webapps.swedbank_psd2_saturn.LocalIntegrationService;

import org.webpki.webapps.swedbank_psd2_saturn.api.OpenBanking;

// Initiation code for KeyGen2

public class KeyProviderInitServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    static Logger logger = Logger.getLogger(KeyProviderInitServlet.class.getCanonicalName());
    
    static final String KEYGEN2_SESSION_ATTR           = "keygen2";
    static final String USERNAME_SESSION_ATTR_PARM     = "userName";  // Dual use
    static final String W3C_PAYMENT_REQUEST_MODE_PARM  = "w3cpr";
    public static final String ACCOUNT_SET_MODE_PARM   = "account";
    
    static final int NAME_MAX_LENGTH                   = 50;  // Reflected in the DB

    static final String INIT_TAG  = "init";     // Note: This is currently also a part of the KeyGen2 client!
    static final String ABORT_TAG = "abort";
    static final String PARAM_TAG = "msg";
    static final String ERROR_TAG = "err";
    
    private static final String BUTTON_ID  = "gokg2";
    private static final String WAITING_ID = "wait";
    private static final String ERROR_ID   = "error";
    
    static final String DEFAULT_USER_NAME_HTML = "Luke Skywalker &#x1f984;";    // Unicorn emoji
    
    static final String BUTTON_TEXT_HTML       = "Start Enrollment &#x1f680;";  // Rocket emoji
    
    static final String ANONYMOUS_JAVA         = "Anonymous " + 
                 new String(Character.toChars(Integer.parseInt("1f47d", 16)));  // E.T. emoji
    
    static String getInvocationUrl(String scheme, HttpSession session) throws IOException {
        ////////////////////////////////////////////////////////////////////////////////////////////
        // The following is the actual contract between an issuing server and a KeyGen2 client.
        // The PUP_INIT_URL argument bootstraps the protocol via an HTTP GET
        ////////////////////////////////////////////////////////////////////////////////////////////
        String urlEncoded = URLEncoder.encode(LocalIntegrationService.keygen2RunUrl, "utf-8");
        return scheme + "://" + MobileProxyParameters.HOST_KEYGEN2 + 
               "?" + MobileProxyParameters.PUP_COOKIE     + "=" + "JSESSIONID%3D" + session.getId() +
               "&" + MobileProxyParameters.PUP_INIT_URL   + "=" + urlEncoded + "%3F" + INIT_TAG + "%3Dtrue" +
               "&" + MobileProxyParameters.PUP_MAIN_URL   + "=" + urlEncoded +
               "&" + MobileProxyParameters.PUP_CANCEL_URL + "=" + urlEncoded + "%3F" + ABORT_TAG + "%3Dtrue" +
               "&" + MobileProxyParameters.PUP_VERSIONS   + "=" + LocalIntegrationService.grantedVersions;
   }
    
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        HTML.standardPage(response, 
            (LocalIntegrationService.useW3cPaymentRequest ?
            "function paymentRequestError(msg) {\n" +
            "  console.info('Payment request error:' + msg);\n" +
            "  document.getElementById('" + WAITING_ID + "').style.display = 'none';\n" +
            "  document.getElementById('" + ERROR_ID + "').innerHTML = msg;\n" +
            "  document.getElementById('" + ERROR_ID + "').style.display = 'block';\n" +
            "  document.getElementById('" + BUTTON_ID + "').style.display = 'block';\n" +
            "}\n\n" +

            "async function enroll() {\n" +
            //////////////////////////////////////////////////////////////////////
            // PaymentRequest for key enrollment?  Right, there is currently no //
            // better way combining the Web and Android applications. You get:  //
            //  - Return value to the invoking Web page                         //
            //  - Invoking Web page security context to the App                 //
            //  - UI wise almost perfect Web2App integration                    //
            //  - Away from having to select browser for App invoked pages      //
            //  - Security beating URL handlers without adding vulnerabilities  //
            //////////////////////////////////////////////////////////////////////
            "  if (window.PaymentRequest) {\n" +
            //==================================================================//
            // It may take a second or two to get PaymentRequest up and         //
            // running.  Indicate that to the user.                             //
            //==================================================================//
            "    document.getElementById('" + BUTTON_ID + "').style.display = 'none';\n" +
            "    document.getElementById('" + WAITING_ID + "').style.display = 'block';\n" +
            //==================================================================//
            // The following code may seem strange but the Web application      //
            // does not create an HttpSession so we do this immediately after   //
            // the user hit the "Enroll" button.  Using fetch() this becomes    //
            // invisible UI wise. The POST provides the current FORM data which //
            // is added to the HttpSession to be created on the server.         //
            //==================================================================//
            "    var formData = new URLSearchParams();\n" +
            "    formData.append('" + USERNAME_SESSION_ATTR_PARM +
              "', document.forms.shoot.elements." + USERNAME_SESSION_ATTR_PARM + ".value);\n" +
            "    formData.append('" + W3C_PAYMENT_REQUEST_MODE_PARM + "', 1);\n" +
            "    try {\n" +
            "      const httpResponse = await fetch('kg2.init', {\n" +
            "        method: 'POST',\n" +
            "        body: formData\n" +
            "      });\n" +
            "      if (httpResponse.status == " + HttpServletResponse.SC_OK + ") {\n" +
            "        const invocationUrl = await httpResponse.text();\n" +
            //==================================================================//
            // Success! Now we can now hook into the W3C PaymentRequest using   //
            // "dummy" payment data.                                            //
            //==================================================================//
            "        const details = {total:{label:'total',amount:{currency:'USD',value:'1.00'}}};\n" +
            "        const supportedInstruments = [{\n" +
            "          supportedMethods: '" + LocalIntegrationService.w3cPaymentRequestUrl + "',\n" +
// Test data
//            "          supportedMethods: 'weird-pay',\n" +
            "          data: {url: invocationUrl}\n" +
// Test data
//            "          supportedMethods: 'basic-card',\n" +
//            "          data: {supportedNetworks: ['visa', 'mastercard']}\n" +
            "        }];\n" +
            "        const payRequest = new PaymentRequest(supportedInstruments, details);\n" +
            "        if (await payRequest.canMakePayment()) {\n" +
            "          const payResponse = await payRequest.show();\n" +
            "          payResponse.complete('success');\n" +
            //==================================================================//
            // Note that success does not necessarily mean that the enrollment  //
            // succeeded, it just means that the result is a redirect URL.      //                                                   //
            //==================================================================//
            "          document.location.href = payResponse.details." +
              MobileProxyParameters.W3CPAY_GOTO_URL + ";\n" +
            "        } else {\n" +
            "          paymentRequestError('App does not seem to be installed');\n" +
            "        }\n" +
            "      } else if (httpResponse.status == " + HttpServletResponse.SC_FORBIDDEN + ") {\n" +
            "        document.location.href = '" + HomeServlet.REDIRECT_TIMEOUT_URI + "';\n" +
            "      } else {\n" +
            "        paymentRequestError('Server error, try again');\n" +
            "      }\n" +
            "    } catch (err) {\n" +
            "      console.error(err);\n" +
            "      paymentRequestError(err.message);\n" +
            "    }\n" +
            "  } else {\n" +
            // The browser does not support PaymentRequest, fallback to the awkward URL handler
            "    document.forms.shoot.submit();\n" +
            "  }\n" +
            "}"
                 :
            "function enroll() {\n" +
            "  document.forms.shoot.submit();\n" +
            "}"),
            "<div class=\"header\">Create Virtual Payment Card</div>" + 
            "<div class=\"centerbox\">" +
              "<table style=\"border-collapse:collapse\">" + 
                "<tr><td>Your name (real or made up):</td></tr>" + 
                "<tr><td>" +
                  "<form name=\"shoot\" method=\"POST\" action=\"kg2.init\">" + 
                    "<input type=\"text\" name=\"" + USERNAME_SESSION_ATTR_PARM + 
                    "\" value=\"" + DEFAULT_USER_NAME_HTML + 
                    "\" size=\"30\" maxlength=\"50\" " + 
                    "style=\"background-color:#def7fc\">" +
                  "</form>" +
                "</td></tr>" + 
              "</table>" +
            "</div>" + 
            "<div class=\"centerbox\">" +
              "This name will be printed on your virtual payment cards." +
            "</div>" + 
            "<div id=\"" + ERROR_ID + "\" " +
              "style=\"color:red;font-weight:bold;padding-top:1em;display:none\"></div>" +
            "<img id=\"" + WAITING_ID + "\" src=\"images/waiting.gif\" " +
              "style=\"padding-top:1em;display:none\" alt=\"waiting\">" +
            "<div id=\"" + BUTTON_ID + "\" class=\"centerbox\">" +
              "<table>" +
                "<tr><td><div class=\"multibtn\" onclick=\"enroll()\">" + BUTTON_TEXT_HTML + 
                "</div></td></tr>" +
              "</table>" +
            "</div>" +
            "<div style=\"padding-top:1.5em;padding-bottom:1em\" class=\"centerbox\">" +
              "<div class=\"description\">If you have not yet " +
              "installed the &quot;Wallet&quot;, this is the time but <i>please do not " +
              "start the application</i>, simply press " +
              "<div style=\"display:inline;background:blue;color:white;" +
              "font-weight:bold;padding:0 0.5em\">&lt;</div> " +
              "after the installation!</i></div>" +
            "</div>" +
            "<div style=\"cursor:pointer;display:flex;justify-content:center;align-items:center\">" +
              "<img src=\"images/google-play-badge.png\" style=\"height:25pt;padding:0 15pt\" alt=\"image\" " +
                "title=\"Android\" onclick=\"document.location.href = " +
                "'https://play.google.com/store/apps/details?id=" +
                MobileProxyParameters.ANDROID_PACKAGE_NAME + "'\">" +
            "</div>");
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
    throws IOException, ServletException {
        // Note: there are three(!) different ways to enter here.
        // 1. From AccountServlet with a selected account parameter
        // 2. From javascript "fetch()" when using W3C PaymentRequest
        // 3. From javascript when using URL handler
        // Case 2 & 3 comes with a user name parameter
        request.setCharacterEncoding("utf-8");
        HttpSession session = request.getSession(false);
        if (session == null) {
            if (request.getParameter(W3C_PAYMENT_REQUEST_MODE_PARM) == null) {
                // Case 3
                response.sendRedirect(HomeServlet.REDIRECT_TIMEOUT_URI);
            } else {
                // Case 2
                response.sendError(HttpServletResponse.SC_FORBIDDEN);
            }
            return;
        }
        String account = request.getParameter(ACCOUNT_SET_MODE_PARM);
        String userName = request.getParameter(USERNAME_SESSION_ATTR_PARM);
        if (account != null) {
            // Case 1

            // We are still talking Open Banking
            // Client side provided data should always be validated
            OpenBanking.getOpenBanking(request, response).setAndValidateAccountId(account);

            // Initiate KeyGen2
            ServerState serverState =
                    new ServerState(new KeyGen2SoftHSM(LocalIntegrationService.keyManagementKey), 
                                    LocalIntegrationService.keygen2RunUrl,
                                    LocalIntegrationService.serverCertificate,
                                    null);
            session.setAttribute(KEYGEN2_SESSION_ATTR, serverState);
            response.sendRedirect("kg2.init");
            return;
        }
        if (userName == null || (userName = userName.trim()).isEmpty()) {
            userName = ANONYMOUS_JAVA;
        }
        if (userName.length() > NAME_MAX_LENGTH) {
            userName = userName.substring(0, NAME_MAX_LENGTH);
        }
        session.setAttribute(USERNAME_SESSION_ATTR_PARM, userName);
        if (request.getParameter(W3C_PAYMENT_REQUEST_MODE_PARM) == null) {
            // Case 3
            HTML.standardPage(
                response,
                "document.addEventListener('DOMContentLoaded', function() {\n" +
                "  document.location.href = '" + 
                    getInvocationUrl(MobileProxyParameters.SCHEME_URLHANDLER, session) + 
                    "#Intent;scheme=webpkiproxy;package=" +  
                    MobileProxyParameters.ANDROID_PACKAGE_NAME +
                    ";end';\n" +
                "});\n",
                "<div class=\"header\">Saturn App Bootstrap</div>" +
                "<div class=\"centerbox\">" +
                  "<div class=\"description\">If this is all you get there is " +
                  "probably something wrong with the installation.</div>" +
                "</div>");
        } else {
            // Case 2
/*
            // This code makes the PaymentRequest "gesture" requirement open
            // Chrome's payment dialog which is very confusing for users.
            try {
                Thread.sleep(10000);
            } catch (InterruptedException e) {
            }
*/
            String invocationUrl = getInvocationUrl(MobileProxyParameters.SCHEME_W3CPAY, session);
            logger.info("POST return=" + invocationUrl);
            HTML.output(response, invocationUrl);
        }
    }
}
