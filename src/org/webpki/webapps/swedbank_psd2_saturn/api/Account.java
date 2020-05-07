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

import java.io.Serializable;

import java.math.BigDecimal;

import org.webpki.saturn.common.Currencies;

public class Account implements Serializable {

    private static final long serialVersionUID = 1L;

    String accountId;
    Currencies currency;
    BigDecimal balance;  // May be null
    
    Account() {
        
    }

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
