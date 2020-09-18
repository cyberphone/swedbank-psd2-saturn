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

import org.webpki.saturn.common.MobileProxyParameters;

import org.webpki.webapps.swedbank_psd2_saturn.HomeServlet;
import org.webpki.webapps.swedbank_psd2_saturn.HTML;
import org.webpki.webapps.swedbank_psd2_saturn.SaturnDirectModeService;

import org.webpki.webapps.swedbank_psd2_saturn.api.OpenBanking;

// Initiation code for KeyGen2

public class KeyProviderInitServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    static Logger logger = Logger.getLogger(KeyProviderInitServlet.class.getCanonicalName());
    
    static final String KEYGEN2_SESSION_ATTR           = "keygen2";
    static final String USERNAME_SESSION_ATTR          = "userName";  // Dual use
    static final String CARDTYPE_SESSION_ATTR          = "cardType";  // Dual use
    public static final String METALCARD_PARM          = "metalcard";
    public static final String WHITECARD_PARM          = "whitecard";
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
    
    private static final String THIS_SERVLET   = "kg2.init";
    
    static final String DEFAULT_USER_NAME_HTML = "Luke Skywalker &#x1f984;";    // Unicorn emoji
    static final Object DEFAULT_CARDTYPE_JAVA  = METALCARD_PARM;
    
    
    static final String DEFAULT_USER_NAME_JAVA = "Luke Skywalker " +
            new String(Character.toChars(Integer.parseInt("1f984", 16)));       // Unicorn emoji

    static final String BUTTON_TEXT_HTML       = "Start Enrollment &#x1f680;";  // Rocket emoji

    static final String AFTER_INSTALL_JS       =
            new String(Character.toChars(Integer.parseInt("1f449", 16))) + " Click here AFTER install";
    
    static final String ANONYMOUS_JAVA         = "Anonymous " + 
                 new String(Character.toChars(Integer.parseInt("1f47d", 16)));  // E.T. emoji

    static String getInvocationUrl(String scheme, HttpSession session) throws IOException {
        ////////////////////////////////////////////////////////////////////////////////////////////
        // The following is the actual contract between an issuing server and a KeyGen2 client.
        // The PUP_INIT_URL argument bootstraps the protocol via an HTTP GET
        ////////////////////////////////////////////////////////////////////////////////////////////
        String urlEncoded = URLEncoder.encode(SaturnDirectModeService.keygen2RunUrl, "utf-8");
        return scheme + "://" + MobileProxyParameters.HOST_KEYGEN2 + 
               "?" + MobileProxyParameters.PUP_COOKIE     + "=" + "JSESSIONID%3D" + session.getId() +
               "&" + MobileProxyParameters.PUP_INIT_URL   + "=" + urlEncoded + "%3F" + INIT_TAG + "%3Dtrue" +
               "&" + MobileProxyParameters.PUP_MAIN_URL   + "=" + urlEncoded +
               "&" + MobileProxyParameters.PUP_CANCEL_URL + "=" + urlEncoded + "%3F" + ABORT_TAG + "%3Dtrue" +
               "&" + MobileProxyParameters.PUP_VERSIONS   + "=" + SaturnDirectModeService.androidWebPkiVersions;
    }
    
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws IOException, ServletException {
        HttpSession session = request.getSession(false);
        session.setAttribute(USERNAME_SESSION_ATTR, DEFAULT_USER_NAME_JAVA);
        session.setAttribute(CARDTYPE_SESSION_ATTR, DEFAULT_CARDTYPE_JAVA);
        HTML.standardPage(response, 
            "function paymentRequestError(msg) {\n" +
            "  console.info('Payment request error:' + msg);\n" +
            "  document.getElementById('" + WAITING_ID + "').style.display = 'none';\n" +
            "  document.getElementById('" + ERROR_ID + "').innerHTML = msg;\n" +
            "  document.getElementById('" + ERROR_ID + "').style.display = 'block';\n" +
            "  document.getElementById('" + BUTTON_ID + "').style.display = 'block';\n" +
            "}\n" +
            "async function setUserName() {\n" +
            "  let formData = new URLSearchParams();\n" +
            "  formData.append('" + USERNAME_SESSION_ATTR +
              "', document.forms.shoot.elements." + USERNAME_SESSION_ATTR + ".value);\n" +
            "  formData.append('" + CARDTYPE_SESSION_ATTR +
              "', document.forms.shoot.elements." + CARDTYPE_SESSION_ATTR + ".value);\n" +
            "  formData.append('" + W3C_PAYMENT_REQUEST_MODE_PARM + "', 1);\n" +
            "  try {\n" +
            "    const httpResponse = await fetch('" + THIS_SERVLET + "', {\n" +
            "      method: 'POST',\n" +
            "       body: formData\n" +
            "    });\n" +
            "    if (httpResponse.status == " + HttpServletResponse.SC_OK + ") {\n" +
            "      await httpResponse.text();\n" +
            "    } else {\n" +
            "      paymentRequestError('Server problems, try again!');\n" +
            "    }\n" +
            "  } catch(err) {\n" +
            "    paymentRequestError(err.message);\n" +
            "  }\n" +
            "}\n" +
            "function setCardType(active, passive) {\n" +
            "  document.getElementById(active).style.borderColor = 'blue';\n" +
            "  document.getElementById(passive).style.borderColor = '#a9a9a9';\n" +
            "  document.forms.shoot.elements." + CARDTYPE_SESSION_ATTR + ".value = active;\n" +
            "  setUserName();\n" +
            "}\n" +
            "function waitForBrowserDisplay(result) {\n" +
            "  if (document.querySelector('#" + WAITING_ID + "')) {\n" +
            "    if (result) {\n" +
            "      document.getElementById('" + WAITING_ID + "').style.display = 'none';\n" +
            "      document.getElementById('" + BUTTON_ID + "').style.display = 'block';\n" +
            "    } else {\n" +
            "      document.getElementById('" + BUTTON_ID + "').innerHTML = '" +
                     AFTER_INSTALL_JS + "';\n" +
            "      document.getElementById('" + BUTTON_ID + "').onclick = function() {\n" +
            "        document.location.href = '" + THIS_SERVLET + "';\n" +
            "      }\n" +
            "      paymentRequestError('App does not seem to be installed');\n" +
            "      w3cPaymentRequest = null;\n" +
            "    }\n" +
            "  } else {\n" +
            "    setTimeout(function() {\n" +
            "      waitForBrowserDisplay(result);\n" +
            "    }, 100);\n" +
            "  }\n" +
            "}\n" +
            "let w3cPaymentRequest = null;\n" +
            "if (" +
               (SaturnDirectModeService.useW3cPaymentRequest ? "window.PaymentRequest" : "false") + 
                 ") {\n" +
            //==================================================================//
            // W3C PaymentRequest using dummy data.                             //
            //==================================================================//
            "  const dummyDetails = {total:{label:'total',amount:{currency:'USD',value:'1.00'}}};\n" +
            "  const methodData = [{\n" +
            "    supportedMethods: '" + SaturnDirectModeService.w3cPaymentRequestUrl + "',\n" +
// Test data
//                        "        supportedMethods: 'weird-pay',\n" +
            "    data: ['" + getInvocationUrl(MobileProxyParameters.SCHEME_W3CPAY, session) + "']\n" +
// Test data
//                        "        supportedMethods: 'basic-card',\n" +
//                        "        data: {supportedNetworks: ['visa', 'mastercard']}\n" +
            "  }];\n" +
            "  w3cPaymentRequest = new PaymentRequest(methodData, dummyDetails);\n" +
            // Addresses https://bugs.chromium.org/p/chromium/issues/detail?id=999920#c8
            "  w3cPaymentRequest.canMakePayment().then(function(result) {\n" +
            "    waitForBrowserDisplay(result);\n" +
            "  }).catch(function(err) {\n" +
            "    paymentRequestError(err.message);\n" +
            "  });\n" +
            "} else {\n" +
            "  window.addEventListener('load', (event) => {\n" +
            "    setUserName();\n" +
            "    document.getElementById('" + BUTTON_ID + "').style.display = 'block';\n" +
            "    document.getElementById('" + WAITING_ID + "').style.display = 'none';\n" +
            "  });\n" +
            "}\n" +
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
            "  if (w3cPaymentRequest) {\n" +
            //==================================================================//
            // It may take a second or two to get PaymentRequest up and         //
            // running.  Indicate that to the user.                             //
            //==================================================================//
            "    document.getElementById('" + BUTTON_ID + "').style.display = 'none';\n" +
            "    document.getElementById('" + WAITING_ID + "').style.display = 'block';\n" +
            "    try {\n" +
            "      const payResponse = await w3cPaymentRequest.show();\n" +
            "      payResponse.complete('success');\n" +
            //==================================================================//
            // Note that success does not necessarily mean that the enrollment  //
            // succeeded, it just means that the result is a redirect URL.      //                                                   //
            //==================================================================//
            "      document.location.href = payResponse.details." +
              MobileProxyParameters.W3CPAY_GOTO_URL + ";\n" +
            "    } catch (err) {\n" +
            "      console.error(err);\n" +
            "      paymentRequestError(err.message);\n" +
            "    }\n" +
            "  } else {\n" +
            // The browser does not support PaymentRequest, fallback to the awkward URL handler
            "    document.forms.shoot.submit();\n" +
            "  }\n" +
            "}\n",

            "<div class='header'>Create Virtual Payment Card</div>" + 
            "<form name='shoot' method='POST' action='" + THIS_SERVLET + "'>" + 
              "<div class='centerbox'>" +
                "<table style='border-collapse:collapse'>" + 
                  "<tr><td>Your name (real or made up):</td></tr>" + 
                  "<tr><td>" +
                    "<input type='text' name='" + USERNAME_SESSION_ATTR + 
                      "' value='" + DEFAULT_USER_NAME_HTML + 
                      "' size='30' maxlength='50' " + 
                      "style='background-color:#def7fc' oninput=\"setUserName()\">" +
                  "</td></tr>" + 
                "</table>" +
              "</div>" + 
              "<div class='centerbox'>" +
                "This name will be printed on your virtual payment card." +
              "</div>" + 
              "<div class='centerbox'>" +
                "<div style='margin:1em 0;display:inline-flex;align-items:center'>" +
                  "<div>Card color:</div>" +
                  "<div class='cardselbtn' id='" + METALCARD_PARM +
                    "' onclick=\"setCardType('" + METALCARD_PARM + "','" + WHITECARD_PARM + "')\" " +
                    "style='background-image:url(\"images/metalback.png\");border-color:blue'>" +
                  "</div>" +
                  "<div class='cardselbtn' id='" + WHITECARD_PARM +
                    "' onclick=\"setCardType('" + WHITECARD_PARM + "','" + METALCARD_PARM + "')\" " +
                    "style='border-color:#a9a9a9'>" +
                  "</div>" +
                  "<input type='hidden' name='" + CARDTYPE_SESSION_ATTR + 
                    "' value='" + DEFAULT_CARDTYPE_JAVA + "'>" +
                "</div>" + 
              "</div>" + 
            "</form>" +
            "<div id='" + ERROR_ID + "' style='color:red;font-weight:bold;display:none'></div>" +
            "<img id='" + WAITING_ID + "' src='images/waiting.gif' alt='waiting'>" +
            "<div style='display:flex;justify-content:center'>" +
              "<div id='" + BUTTON_ID + "' style='display:none' class='multibtn' onclick=\"enroll()\">" +
                BUTTON_TEXT_HTML + 
              "</div>" +
            "</div>" + 
            "<div style='padding:3em 0 1em 0' class='centerbox'>" +
              "<div class='description'>If you have not yet " +
              "installed the &quot;Wallet&quot;, this is the time but <i>please do not " +
              "start the application</i>, simply press " +
              "<div style='display:inline;background:blue;color:white;" +
              "font-weight:bold;padding:0 0.5em'>&lt;</div> " +
              "after the installation!</div>" +
            "</div>" +
            "<div style='cursor:pointer;display:flex;justify-content:center;align-items:center'>" +
              "<img src='images/google-play-badge.png' style='height:25pt;padding:0 15pt' alt='image' " +
                "title='Android' onclick=\"document.location.href = '" +
                "https://play.google.com/store/apps/details?id=" +
                MobileProxyParameters.ANDROID_PACKAGE_NAME + "'\">" +
            "</div>");
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
    throws IOException, ServletException {
        // Note: there are three(!) different ways to enter here.
        // 1. From AccountServlet with a selected account parameter
        // 2. From javascript "fetch()"
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
        if (account != null) {
            // Case 1

            // We are still talking Open Banking
            // Client side provided data should always be validated
            OpenBanking.getOpenBanking(request, response).setAndValidateAccount(account);

            // Initiate KeyGen2
            ServerState serverState =
                    new ServerState(new KeyGen2SoftHSM(SaturnDirectModeService.keyManagementKey), 
                                    SaturnDirectModeService.keygen2RunUrl,
                                    SaturnDirectModeService.serverCertificate,
                                    null);
            session.setAttribute(KEYGEN2_SESSION_ATTR, serverState);
            response.sendRedirect(THIS_SERVLET);
            return;
        }

        String userName = request.getParameter(USERNAME_SESSION_ATTR);
        if (userName != null) {
            userName = userName.trim();
            if (userName.isEmpty()) {
                userName = ANONYMOUS_JAVA;
            } else if (userName.length() > NAME_MAX_LENGTH) {
                userName = userName.substring(0, NAME_MAX_LENGTH);
            }
            session.setAttribute(USERNAME_SESSION_ATTR, userName);
        }

        String cardType = request.getParameter(CARDTYPE_SESSION_ATTR);
        if (cardType != null) {
            session.setAttribute(CARDTYPE_SESSION_ATTR, cardType);
        }

        if (request.getParameter(W3C_PAYMENT_REQUEST_MODE_PARM) == null) {
            // Case 3
            HTML.standardPage(
                response,
                "window.addEventListener('load', (event) => {\n" +
                "  document.location.href = '" + 
                    getInvocationUrl(MobileProxyParameters.SCHEME_URLHANDLER, session) + 
                    "#Intent;scheme=webpkiproxy;package=" +  
                    MobileProxyParameters.ANDROID_PACKAGE_NAME +
                    ";end';\n" +
                "});\n",
                "<div class='header'>Saturn App Bootstrap</div>" +
                "<div class='centerbox'>" +
                  "<div class='description'>If this is all you get there is " +
                  "probably something wrong with the installation.</div>" +
                "</div>");
        } else {
            // Case 2
            HTML.output(response, "");
        }
    }
}
