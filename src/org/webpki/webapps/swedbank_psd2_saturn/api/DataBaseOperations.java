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
import java.sql.SQLException;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.webpki.crypto.HashAlgorithms;
import org.webpki.webapps.swedbank_psd2_saturn.LocalIntegrationService;

public class DataBaseOperations {

    static Logger logger = Logger.getLogger(DataBaseOperations.class.getCanonicalName());
    
    public static String createCredential(String accountId,         // IBAN
                                          String name,              // On the card
                                          String methodUri,         // Saturn method
                                          PublicKey payReq,         // Payment authorization
                                          PublicKey optionalBalReq) // Not yet...
    throws SQLException, IOException {
        try {

/*
            CREATE PROCEDURE CreateCredentialSP (OUT p_CredentialId INT,
                                                 IN p_AccountId VARCHAR(30),
                                                 IN p_Name VARCHAR(50),
                                                 IN p_MethodUri VARCHAR(50),
                                                 IN p_S256PayReq BINARY(32),
                                                 IN p_S256BalReq BINARY(32))
*/

            try (Connection connection = LocalIntegrationService.jdbcDataSource.getConnection();
                 CallableStatement stmt = 
                    connection.prepareCall("{call CreateCredentialSP(?,?,?,?,?,?)}");) {
                stmt.registerOutParameter(1, java.sql.Types.INTEGER);
                stmt.setString(2, accountId);
                stmt.setString(3, name);
                stmt.setString(4, methodUri);
                stmt.setBytes(5, s256(payReq));
                stmt.setBytes(6, s256(optionalBalReq));
                stmt.execute();
                return String.valueOf(stmt.getInt(1));
            }
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database problem", e);
            throw e;
        }            
    }

    public static class AuthenticationResult {
        public String error;
        public String name;
        public String accountId;
    }
    
    public static AuthenticationResult authenticatePayReq(Connection connection,
                                                          String credentialId,
                                                          PublicKey payReq)
    throws SQLException, IOException {
        try {

/*
            CREATE PROCEDURE AuthenticatePayReqSP (OUT p_Error INT,
                                                   OUT p_Name VARCHAR(50),
                                                   OUT p_AccountId VARCHAR(30),
                                                   IN p_CredentialId INT,
                                                   IN p_S256PayReq BINARY(32))
 
*/

            try (CallableStatement stmt = 
                    connection.prepareCall("{call AuthenticatePayReqSP(?,?,?,?,?)}");) {
                stmt.registerOutParameter(1, java.sql.Types.INTEGER);
                stmt.registerOutParameter(2, java.sql.Types.VARCHAR);
                stmt.registerOutParameter(3, java.sql.Types.VARCHAR);
                stmt.setInt(4, Integer.valueOf(credentialId));
                stmt.setBytes(5, s256(payReq));
                stmt.execute();
                AuthenticationResult authenticationResult = new AuthenticationResult();
                int errorCode = stmt.getInt(1);
                if (errorCode  == 0) {
                    authenticationResult.name = stmt.getString(2);
                    authenticationResult.accountId = stmt.getString(3);
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
}
