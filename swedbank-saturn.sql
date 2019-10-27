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
-- # Open Banking APIs.  The database holds data for           #
-- # Credentials and Transactions                              #
-- #############################################################

USE SWEDBANK_SATURN;

/*=============================================*/
/*                CREDENTIALS                  */
/*=============================================*/

CREATE TABLE CREDENTIALS
  (

-- Note: a Credential holds an external representation of an Account ID
-- like an IBAN or Card Number + and an Authorization key

    Id          INT           NOT NULL  AUTO_INCREMENT,                  -- Unique ID

    AccountId   VARCHAR(30)   NOT NULL,                                  -- Account Reference
    
    MethodUri   VARCHAR(50)   NOT NULL,                                  -- Payment method

    Name        VARCHAR(50)   NOT NULL,                                  -- Human name
    
    UserId      INT           NOT NULL,                                  -- For OAuth2 tokens

    Created     TIMESTAMP     NOT NULL  DEFAULT CURRENT_TIMESTAMP,       -- Administrator data

-- Authentication of user authorization signatures is performed
-- by verifying that both SHA256 of the public key (in X.509 DER
-- format) and claimed Id match.

    S256PayReq  BINARY(32)    NOT NULL,                                  -- Payment request key hash 

    S256BalReq  BINARY(32)    NULL,                                      -- Optional: balance key hash 

    PRIMARY KEY (Id),
    FOREIGN KEY (UserId) REFERENCES OAUTH2TOKENS(UserId)
  ) AUTO_INCREMENT=200500123;                                            -- Brag about "users" :-)


/*=============================================*/
/*                OAUTH2TOKENS                 */
/*=============================================*/

CREATE TABLE OAUTH2TOKENS
  (

-- Note: since the Swedbank "sandbox" only supports a single user
-- this table isn't terribly exciting

    UserId      INT           NOT NULL  DEFAULT 1,                       -- Unique User ID

    AccessToken VARCHAR(36)   NOT NULL,                                  -- The one we normally use
    
    RefreshToken VARCHAR(36)  NOT NULL,                                  -- Refreshing

    PRIMARY KEY (UserId)
  );


/*=============================================*/
/*               TRANSACTIONS                  */
/*=============================================*/

CREATE TABLE TRANSACTIONS
  (
    Id          INT           NOT NULL  UNIQUE,                          -- Unique Transaction ID

    CredentialId INT          NOT NULL  UNIQUE,                          /* Credential ID used */

    Amount      DECIMAL(8,2)  NOT NULL,                                  -- The Amount involved

    PayeeAccount VARCHAR(50)  NOT NULL,                                  -- Destination account ID

    PayeeName  VARCHAR(50),                                              -- Optional Payee name

    PayeeReference VARCHAR(50),                                          /* Optional Payee reference
                                                                            like internal order ID */

    Created     TIMESTAMP     NOT NULL  DEFAULT CURRENT_TIMESTAMP,       -- Administrator data
    PRIMARY KEY (Id),
    FOREIGN KEY (CredentialId) REFERENCES CREDENTIALS(Id) ON DELETE CASCADE
  );


/*=============================================*/
/*            TRANSACTION_COUNTER              */
/*=============================================*/

CREATE TABLE TRANSACTION_COUNTER
  (
-- MySQL 5.7 auto increment is unreliable for this application since it
-- loses track for power fails if TRANSACTIONS are emptied like in the demo.

-- Therefore we use a regular table with a single column and row.

    Next        INT           NOT NULL                                   -- Monotonic counter

  );

INSERT INTO TRANSACTION_COUNTER(Next) VALUES(100345078);

INSERT INTO OAUTH2TOKENS(AccessToken, RefreshToken) VALUES("", "");

DELIMITER //


-- This particular implementation builds on creating the pending transaction ID
-- before the transaction is performed.  There are pros and cons with all such
-- schemes. This one leave "holes" in the sequence for failed transactions.

CREATE FUNCTION GetNextTransactionIdSP () RETURNS INT
  BEGIN
     UPDATE TRANSACTION_COUNTER SET Next = LAST_INSERT_ID(Next + 1) LIMIT 1;
     RETURN LAST_INSERT_ID();
  END
//

CREATE PROCEDURE CreateCredentialSP (OUT p_CredentialId INT,
                                     IN p_AccountId VARCHAR(30),
                       	             IN p_Name VARCHAR(50),
                                     IN p_MethodUri VARCHAR(50),
                                     IN p_S256PayReq BINARY(32),
                                     IN p_S256BalReq BINARY(32))
  BEGIN
    INSERT INTO CREDENTIALS(AccountId, Name, MethodUri, S256PayReq, S256BalReq) 
        VALUES(p_AccountId, p_Name, p_MethodUri, p_S256PayReq, p_S256BalReq);
    SET p_CredentialId = LAST_INSERT_ID();
  END
//

CREATE PROCEDURE AuthenticatePayReqSP (OUT p_Error INT,
                                       OUT p_Name VARCHAR(50),
                                       OUT p_AccountId VARCHAR(30),
                                       IN p_CredentialId INT,
                                       IN p_S256PayReq BINARY(32))
  BEGIN
    SELECT CREDENTIALS.Name, CREDENTIALS.AccountId INTO p_Name, p_AccountId FROM CREDENTIALS 
        WHERE CREDENTIALS.Id = p_CredentialId AND CREDENTIALS.S256PayReq = p_S256PayReq;
    IF p_Name IS NULL THEN   -- Failed => Find reason
      IF EXISTS (SELECT * FROM CREDENTIALS WHERE CREDENTIALS.Id = p_CredentialId) THEN
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

CALL CreateCredentialSP(@credid, 
                        "SE6767676767676767676",
                        "Luke Skywalker",
                        "https://supercard.com",
                        x'b3b76a196ced26e7e5578346b25018c0e86d04e52e5786fdc2810a2a10bd104a',
                        NULL);
SELECT @credid;


