-- SQL Script for MySQL 5.7
--
-- root privileges are required!!!
--
-- Clear and create DB to begin with
--
DROP DATABASE IF EXISTS SWEDBANK_SATURN;
CREATE DATABASE SWEDBANK_SATURN CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
--
-- Create our single user
--
DROP USER IF EXISTS 'swedbank-saturn'@localhost;
CREATE USER 'swedbank-saturn'@localhost IDENTIFIED BY 'foo123';
--
-- Give this user access
--
GRANT ALL ON SWEDBANK_SATURN.* TO 'swedbank-saturn'@localhost;
GRANT SELECT ON mysql.proc TO 'swedbank-saturn'@localhost;
--
-- Create tables and stored procedures
--
-- #############################################################
-- # This is the Payer side of a PoC database for "Dual Mode"  #
-- # Open Banking APIs.  The database holds information about  #
-- # Credentials and OAuth tokens                              #
-- #############################################################

USE SWEDBANK_SATURN;

/*=============================================*/
/*                OAUTH2TOKENS                 */
/*=============================================*/

CREATE TABLE OAUTH2TOKENS
  (

    IdentityToken   VARCHAR(50) NOT NULL UNIQUE,                        -- Unique User ID

    AccessToken     CHAR(36)    NOT NULL,                               -- The one we normally use
    
    RefreshToken    CHAR(36)    NOT NULL,                               -- Refreshing
    
    Expires         INT         NOT NULL,                               -- In UNIX "epoch" style
                                                                        
 
    PRIMARY KEY (IdentityToken)
  );


/*=============================================*/
/*                CREDENTIALS                  */
/*=============================================*/

CREATE TABLE CREDENTIALS
  (

-- Note: a Credential holds an external representation of an Account ID
-- like an IBAN or Card Number + and an Authorization key

    CredentialId    INT         NOT NULL  AUTO_INCREMENT,               -- Unique ID

    AccountId       VARCHAR(30) NOT NULL,                               -- Account Reference
    
    MethodUri       VARCHAR(50) NOT NULL,                               -- Payment method

    HumanName       VARCHAR(50) NOT NULL,                               -- "Card holder"
    
    IdentityToken   VARCHAR(50) NOT NULL,                               -- For OAuth2 tokens

    Created         TIMESTAMP   NOT NULL  DEFAULT CURRENT_TIMESTAMP,    -- Administrator data

-- Authentication of user authorization signatures is performed
-- by verifying that both SHA256 of the public key (in X.509 DER
-- format) and claimed CredentialId match.

    S256PayReq      BINARY(32)  NOT NULL,                               -- Payment request key hash 

    S256BalReq      BINARY(32)  NULL,                                   -- Optional: Balance key hash 

    PRIMARY KEY (CredentialId),
    FOREIGN KEY (IdentityToken) REFERENCES OAUTH2TOKENS(IdentityToken) ON DELETE CASCADE
  ) AUTO_INCREMENT=200500123;                                           -- Brag about "users" :-)


-- We only have a single user due to limitations of the Swedbank "sandbox"

SET @IdentityToken = "20010101-1234";

INSERT INTO OAUTH2TOKENS(IdentityToken, AccessToken, RefreshToken, Expires) 
    VALUES(@IdentityToken,
           "00000000-0000-0000-0000-000000000000",
           "00000000-0000-0000-0000-000000000000",
           0);

DELIMITER //


CREATE PROCEDURE CreateCredentialSP (OUT p_CredentialId INT,
                                     IN p_IdentityToken VARCHAR(50),
                                     IN p_AccountId VARCHAR(30),
                                     IN p_Name VARCHAR(50),
                                     IN p_MethodUri VARCHAR(50),
                                     IN p_S256PayReq BINARY(32),
                                     IN p_S256BalReq BINARY(32))
  BEGIN
    INSERT INTO CREDENTIALS(AccountId, HumanName, MethodUri, IdentityToken, S256PayReq, S256BalReq) 
        VALUES(p_AccountId, p_Name, p_MethodUri, p_IdentityToken, p_S256PayReq, p_S256BalReq);
    SET p_CredentialId = LAST_INSERT_ID();
  END
//

CREATE PROCEDURE StoreAccessTokenSP (IN p_AccessToken CHAR(36),
                                     IN p_RefreshToken CHAR(36),
                                     IN p_Expires INT,
                                     IN p_IdentityToken VARCHAR(50))
  BEGIN
    IF EXISTS (SELECT * FROM OAUTH2TOKENS WHERE OAUTH2TOKENS.IdentityToken = p_IdentityToken) THEN
      UPDATE OAUTH2TOKENS SET AccessToken = p_AccessToken, 
                              RefreshToken = p_RefreshToken,
                              Expires = p_Expires
          WHERE OAUTH2TOKENS.IdentityToken = p_IdentityToken;
    ELSE
      INSERT INTO OAUTH2TOKENS(IdentityToken, AccessToken, RefreshToken, Expires) 
          VALUES(p_IdentityToken, p_AccessToken, p_RefreshToken, p_Expires);
    END IF;
  END
//

CREATE PROCEDURE AuthenticatePayReqSP (OUT p_Error INT,
                                       OUT p_HumanName VARCHAR(50),
                                       OUT p_AccountId VARCHAR(30),
                                       OUT p_AccessToken CHAR(36),
                                       IN p_CredentialId INT,
                                       IN p_S256PayReq BINARY(32))
  BEGIN
    SELECT CREDENTIALS.HumanName, 
           CREDENTIALS.AccountId, 
           OAUTH2TOKENS.AccessToken
        INTO 
           p_HumanName,
           p_AccountId,
           p_AccessToken
        FROM CREDENTIALS INNER JOIN OAUTH2TOKENS ON CREDENTIALS.IdentityToken = OAUTH2TOKENS.IdentityToken 
        WHERE CREDENTIALS.CredentialId = p_CredentialId AND CREDENTIALS.S256PayReq = p_S256PayReq;
    IF p_AccessToken IS NULL THEN   -- Failed => Find reason
      IF EXISTS (SELECT * FROM CREDENTIALS WHERE CREDENTIALS.CredentialId = p_CredentialId) THEN
        SET p_Error = 1;       -- Key does not match credentialId
      ELSE
        SET p_Error = 2;       -- Credential not found
      END IF;
    ELSE                       
      SET p_Error = 0;         -- Success
    END IF;
  END
//

DELIMITER ;

-- Run a few tests

set @PaymentKey = x'b3b76a196ced26e7e5578346b25018c0e86d04e52e5786fdc2810a2a10bd104a';

CALL CreateCredentialSP (@CredentialId, 
                         @IdentityToken,
                         "SE6767676767676767676",
                         "Luke Skywalker",
                         "https://supercard.com",
                         @PaymentKey,
                         NULL);
                        
SELECT @CredentialId;

CALL AuthenticatePayReqSP (@Error,
                           @HumanName,
                           @AccountId,
                           @AccessToken,
                           @CredentialId,
                           @PaymentKey);

SELECT @Error, @HumanName, @AccountId, @AccessToken;

set @NonMatchingPaymentKey = x'b3b76a196ced26e7e5578346b25018c0e86d04e52e5786fdc2810a2a10bd104b';

CALL AuthenticatePayReqSP (@Error,
                           @HumanName,
                           @AccountId,
                           @AccessToken,
                           @CredentialId,
                           @NonMatchingPaymentKey);

SELECT @Error, @HumanName, @AccountId, @AccessToken;

-- Remove all test data

DELETE FROM OAUTH2TOKENS;
