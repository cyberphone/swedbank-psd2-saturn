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
package org.webpki.webapps.swedbank_psd2_saturn.api;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.webpki.crypto.HashAlgorithms;

import org.webpki.webapps.swedbank_psd2_saturn.SaturnDirectModeService;

// All database operation are performed in this class

class DataBaseOperations {

    static Logger logger = Logger.getLogger(DataBaseOperations.class.getCanonicalName());
    
    static void failed(Exception e) {
        logger.log(Level.SEVERE, "Database problem", e);
    }
    
    static String createCredential(String identityToken,        // Credential bound to user
                                   String accountId,            // IBAN
                                   String humanName,            // On the card
                                   String ipAddress,            // "Statistics"
                                   String paymentMethodUrl,     // Saturn method
                                   PublicKey authorizationKey,  // Payment authorization
                                   PublicKey balanceRequestKey) // Balance request authorization
    throws SQLException, IOException, GeneralSecurityException {
        try {

/*
            CREATE PROCEDURE CreateCredentialSP (OUT p_CredentialId INT,
                                                 IN p_IdentityToken VARCHAR(50),
                                                 IN p_AccountId VARCHAR(30),
                                                 IN p_HumanName VARCHAR(50),
                                                 IN p_IpAddress VARCHAR(50),
                                                 IN p_PaymentMethodUrl VARCHAR(50),
                                                 IN p_S256PayReq BINARY(32),
                                                 IN p_S256BalReq BINARY(32))
*/

            try (Connection connection = SaturnDirectModeService.jdbcDataSource.getConnection();
                 CallableStatement stmt = 
                    connection.prepareCall("{call CreateCredentialSP(?,?,?,?,?,?,?,?)}");) {
                stmt.registerOutParameter(1, java.sql.Types.INTEGER);
                stmt.setString(2, identityToken);
                stmt.setString(3, accountId);
                stmt.setString(4, humanName);
                stmt.setString(5, ipAddress);
                stmt.setString(6, paymentMethodUrl);
                stmt.setBytes(7, s256(authorizationKey));
                stmt.setBytes(8, s256(balanceRequestKey));
                stmt.execute();
                return String.valueOf(stmt.getInt(1));
            }
        } catch (SQLException e) {
            failed(e);
            throw e;
        }            
    }

    static OpenBanking.AuthenticationResult authenticatePayReq(String credentialId,
                                                               String accountId,
                                                               String paymentMethodUrl,
                                                               PublicKey authorizationKey)
    throws SQLException, IOException, GeneralSecurityException {
        try {

/*
        CREATE PROCEDURE AuthenticatePayReqSP (OUT p_Error INT,
                                               OUT p_HumanName VARCHAR(50),
                                               OUT p_IdentityToken VARCHAR(50),
        
        -- Note: the assumption is that the following variables are non-NULL otherwise
        -- you may get wrong answer due to the (weird) way SQL deals with comparing NULL!

                                               IN p_CredentialId INT,
                                               IN p_AccountId VARCHAR(30),
                                               IN p_PaymentMethodUrl VARCHAR(50),
                                               IN p_S256PayReq BINARY(32))
*/

            try (Connection connection = SaturnDirectModeService.jdbcDataSource.getConnection();
                 CallableStatement stmt = 
                    connection.prepareCall("{call AuthenticatePayReqSP(?,?,?,?,?,?,?)}");) {
                stmt.registerOutParameter(1, java.sql.Types.INTEGER);
                stmt.registerOutParameter(2, java.sql.Types.VARCHAR);
                stmt.registerOutParameter(3, java.sql.Types.VARCHAR);
                stmt.setInt(4, Integer.valueOf(credentialId));
                stmt.setString(5, accountId);
                stmt.setString(6,  paymentMethodUrl);
                stmt.setBytes(7, s256(authorizationKey));
                stmt.execute();
                OpenBanking.AuthenticationResult authenticationResult = 
                        new OpenBanking.AuthenticationResult();
                switch (stmt.getInt(1)) {
                    case 0:
                        authenticationResult.humanName = stmt.getString(2);
                        authenticationResult.identityToken = stmt.getString(3);
                        break;

                    case 1:
                        authenticationResult.error = "Credential not found";
                        break;

                    case 2:
                        authenticationResult.error = "AccountId mismatch";
                        break;

                    case 3:
                        authenticationResult.error = "Key does not match credentialId";
                        break;
                    
                    default:
                        authenticationResult.error = "Payment method mismatch";
                        break;
                }
                return authenticationResult;
            }
        } catch (SQLException e) {
            failed(e);
            throw e;
        }            
    }

    static OpenBanking.AuthenticationResult authenticateBalReq(String credentialId,
                                                               String accountId,
                                                               PublicKey balanceKey)
        throws SQLException, IOException, GeneralSecurityException {
        try {
        
/*
        CREATE PROCEDURE AuthenticateBalReqSP (OUT p_Error INT,
                                               OUT p_IdentityToken VARCHAR(50),
        
        -- Note: the assumption is that the following variables are non-NULL otherwise
        -- you may get wrong answer due to the (weird) way SQL deals with comparing NULL!
        
                                               IN p_CredentialId INT,
                                               IN p_AccountId VARCHAR(30),
                                               IN p_S256BalKey BINARY(32))
*/
        
        try (Connection connection = SaturnDirectModeService.jdbcDataSource.getConnection();
                CallableStatement stmt = connection.prepareCall("{call AuthenticateBalReqSP(?,?,?,?,?)}");) {
            stmt.registerOutParameter(1, java.sql.Types.INTEGER);
            stmt.registerOutParameter(2, java.sql.Types.VARCHAR);
            stmt.setInt(3, Integer.valueOf(credentialId));
            stmt.setString(4, accountId);
            stmt.setBytes(5, s256(balanceKey));
            stmt.execute();
            OpenBanking.AuthenticationResult authenticationResult = new OpenBanking.AuthenticationResult();
            switch (stmt.getInt(1)) {
                case 0:
                    authenticationResult.identityToken = stmt.getString(2);
                    break;
            
                case 1:
                    authenticationResult.error = "Credential not found";
                    break;
            
                case 2:
                    authenticationResult.error = "AccountId mismatch";
                    break;
            
                default:
                    authenticationResult.error = "Key does not match credentialId";
                    break;
                }
                return authenticationResult;
            }
        } catch (SQLException e) {
            failed(e);
            throw e;
        }
    }

    private static byte[] s256(PublicKey publicKey) 
            throws IOException, GeneralSecurityException {
        return publicKey == null ? null : HashAlgorithms.SHA256.digest(publicKey.getEncoded());
    }

    public static void scanAll(OpenBanking.CallBack callBack) throws IOException {
        try {
            try (Connection connection = SaturnDirectModeService.jdbcDataSource.getConnection();
                 PreparedStatement stmt = 
                         connection.prepareStatement("SELECT * FROM OAUTH2TOKENS");
                 ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    callBack.refreshToken(rs.getString("IdentityToken"),
                                          rs.getString("RefreshToken"),
                                          rs.getInt("Expires"));
                }
            }
        } catch (SQLException e) {
            failed(e);
            throw new IOException(e);
        }
    }

    static String getAccessToken(String identityToken) throws IOException {
        try {
            try (Connection connection = SaturnDirectModeService.jdbcDataSource.getConnection();
                 PreparedStatement stmt = connection
            .prepareStatement("SELECT AccessToken FROM OAUTH2TOKENS WHERE IdentityToken=?");) {
                stmt.setString(1, identityToken);
                try (ResultSet rs = stmt.executeQuery();) {
                    rs.next();
                    return rs.getString(1);
                }
            }
        } catch (SQLException e) {
            failed(e);
            throw new IOException(e);
        }
    }

    static void storeAccessToken(OpenBanking openBanking,
                                 String accessToken,
                                 String refreshToken,
                                 int expires) throws IOException {
        try {

/*
            CREATE PROCEDURE StoreAccessTokenSP (IN p_AccessToken CHAR(36),
                                                 IN p_RefreshToken CHAR(36),
                                                 IN p_Expires INT,
                                                 IN p_IdentityToken VARCHAR(50))
*/

            try (Connection connection = SaturnDirectModeService.jdbcDataSource.getConnection();
                 CallableStatement stmt = connection.prepareCall("{call StoreAccessTokenSP(?,?,?,?)}");) {
                stmt.setString(1, accessToken);
                stmt.setString(2, refreshToken);
                stmt.setInt(3, expires);
                stmt.setString(4, openBanking.identityToken);
                stmt.execute();
            }
        } catch (SQLException e) {
            failed(e);
            throw new IOException(e);
        }
    }
}
