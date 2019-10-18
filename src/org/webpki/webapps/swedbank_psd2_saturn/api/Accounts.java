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
package org.webpki.webapps.swedbank_psd2_saturn.api;

import java.io.IOException;
import java.io.Serializable;

import java.math.BigDecimal;

import java.util.LinkedHashMap;

import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONObjectReader;

import org.webpki.saturn.common.Currencies;

public class Accounts implements Serializable {

    private static final long serialVersionUID = 1L;

    Accounts(JSONObjectReader accountData) throws IOException {
        // Likely to be provider dependent
        JSONArrayReader accountsArray = accountData.getArray("accounts");
        while (accountsArray.hasMore()) {
            JSONObjectReader accountEntry = accountsArray.getObject();
            Account account = new Account();
            accounts.put(account.accountId = 
                    accountEntry.getString(APICore.PRIMARY_ACCOUNT_TYPE), account);
            if (accountEntry.hasProperty("balances")) {
                JSONObjectReader balance = 
                        accountEntry.getArray("balances").getObject().getObject("balanceAmount");
                account.balance = new BigDecimal(balance.getString("amount"));
                account.currency = Currencies.valueOf(balance.getString("currency"));
            }
        }
    }

    LinkedHashMap<String, Account> accounts = new LinkedHashMap<String, Account>();

    public static class Account {
        String accountId;
        Currencies currency;
        BigDecimal balance;  // May be null

        public String getAccountId() {
            return accountId;
        }

        public BigDecimal getBalance() {
            return balance;
        }
        
        public Currencies getCurrency() {
            return currency;
        }
    }

    public String[] getAccountIds() {
        return accounts.keySet().toArray(new String[0]);
    }

    public Account getAccount(String accountId) throws IOException {
        Account account = accounts.get(accountId);
        if (account == null) {
            throw new IOException("No such account: " + accountId);
        }
        return account;
    }
}
