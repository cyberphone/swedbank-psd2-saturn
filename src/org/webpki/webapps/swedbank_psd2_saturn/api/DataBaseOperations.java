/*
 *  Copyright 2015-2018 WebPKI.org (http://webpki.org).
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

import java.security.PublicKey;

import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.webpki.crypto.HashAlgorithms;

import org.webpki.webapps.swedbank_psd2_saturn.LocalIntegrationService;

// All database operation are performed in this class

class DataBaseOperations {

    static Logger logger = Logger.getLogger(DataBaseOperations.class.getCanonicalName());
    
    static String createCredential(String accountId,         // IBAN
                                   String name,              // On the card
                                   String methodUri,         // Saturn method
                                   String userId,            // Just one
                                   PublicKey payReq,         // Payment authorization
                                   PublicKey optionalBalReq) // Not yet...
    throws SQLException, IOException {
        try {

/*
            CREATE PROCEDURE CreateCredentialSP (OUT p_CredentialId INT,
                                                 IN p_UserId CHAR(13),
                                                 IN p_AccountId VARCHAR(30),
                                                 IN p_Name VARCHAR(50),
                                                 IN p_MethodUri VARCHAR(50),
                                                 IN p_S256PayReq BINARY(32),
                                                 IN p_S256BalReq BINARY(32))
*/

            try (Connection connection = LocalIntegrationService.jdbcDataSource.getConnection();
                 CallableStatement stmt = 
                    connection.prepareCall("{call CreateCredentialSP(?,?,?,?,?,?,?)}");) {
                stmt.registerOutParameter(1, java.sql.Types.INTEGER);
                stmt.setString(2, userId);
                stmt.setString(3, accountId);
                stmt.setString(4, name);
                stmt.setString(5, methodUri);
                stmt.setBytes(6, s256(payReq));
                stmt.setBytes(7, s256(optionalBalReq));
                stmt.execute();
                return String.valueOf(stmt.getInt(1));
            }
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database problem", e);
            throw e;
        }            
    }

    static OpenBanking.AuthenticationResult authenticatePayReq(String credentialId,
                                                               PublicKey payReq)
    throws SQLException, IOException {
        try {

/*
            CREATE PROCEDURE AuthenticatePayReqSP (OUT p_Error INT,
                                                   OUT p_Name VARCHAR(50),
                                                   OUT p_AccountId VARCHAR(30),
                                                   OUT p_AccessToken CHAR(36),
                                                   IN p_CredentialId INT,
                                                   IN p_S256PayReq BINARY(32))
*/

            try (Connection connection = LocalIntegrationService.jdbcDataSource.getConnection();
                 CallableStatement stmt = 
                    connection.prepareCall("{call AuthenticatePayReqSP(?,?,?,?,?,?)}");) {
                stmt.registerOutParameter(1, java.sql.Types.INTEGER);
                stmt.registerOutParameter(2, java.sql.Types.VARCHAR);
                stmt.registerOutParameter(3, java.sql.Types.VARCHAR);
                stmt.registerOutParameter(4, java.sql.Types.CHAR);
                stmt.setInt(5, Integer.valueOf(credentialId));
                stmt.setBytes(6, s256(payReq));
                stmt.execute();
                OpenBanking.AuthenticationResult authenticationResult = 
                        new OpenBanking.AuthenticationResult();
                int errorCode = stmt.getInt(1);
                if (errorCode  == 0) {
                    authenticationResult.name = stmt.getString(2);
                    authenticationResult.accountId = stmt.getString(3);
                    authenticationResult.accessToken = stmt.getString(4);
                } else {
                    authenticationResult.error = errorCode == 1 ?
                              "Key does not match credentialId" : "Credential not found";
                }
                return authenticationResult;
            }
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database problem", e);
            throw e;
        }            
    }

    private static byte[] s256(PublicKey publicKey) throws IOException {
        return publicKey == null ? null : HashAlgorithms.SHA256.digest(publicKey.getEncoded());
    }

    static String getAccessToken(String userId) throws IOException {
        try {

/*
            CREATE PROCEDURE GetAccessTokenSP (OUT p_AccessToken CHAR(36),
                                               IN p_UserId CHAR(13))
*/

            try (Connection connection = LocalIntegrationService.jdbcDataSource.getConnection();
                 CallableStatement stmt = connection.prepareCall("{call GetAccessTokenSP(?,?)}");) {
                stmt.registerOutParameter(1, java.sql.Types.CHAR);
                stmt.setString(2, userId);
                stmt.execute();
                return stmt.getString(1);
            }
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database problem", e);
            throw new IOException(e);
        }
    }

    public static void scanAll(OpenBanking.CallBack callBack) throws IOException {
        try {
             try (Connection connection = LocalIntegrationService.jdbcDataSource.getConnection();
                 Statement stmt = connection.createStatement();
                 ResultSet rs = stmt.executeQuery("SELECT * FROM OAUTH2TOKENS")) {
                while (rs.next()) {
                    callBack.refreshToken(rs.getString("UserId"),
                                          rs.getString("RefreshToken"),
                                          rs.getInt("Expires"));
                }
            }
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database problem", e);
            throw new IOException(e);
        }
    }

    static void storeAccessToken(OpenBanking openBanking) throws IOException {
        try {

/*
            CREATE PROCEDURE StoreAccessTokenSP (IN p_AccessToken CHAR(36),
                                                 IN p_RefreshToken CHAR(36),
                                                 IN p_Expires INT,
                                                 IN p_UserId CHAR(13))
*/

            try (Connection connection = LocalIntegrationService.jdbcDataSource.getConnection();
                 CallableStatement stmt = connection.prepareCall("{call StoreAccessTokenSP(?,?,?,?)}");) {
                stmt.setString(1, openBanking.accessToken);
                stmt.setString(2, openBanking.refreshToken);
                stmt.setLong(3, openBanking.expires);
                stmt.setString(4, openBanking.userId);
                stmt.execute();
            }
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database problem", e);
            throw new IOException(e);
        }
    }
}
