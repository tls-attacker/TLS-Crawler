/*
 * TLS-Crawler is able to perform large scale
 * analyses on censorship.
 *
 * Copyright 2018-2022
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlscrawler.scans;

public enum ScanType {
    // Scan of a TLS server using the TLS-Scanner
    TLS,
    // Wether the server answers to ping
    PING,
    // Analyzes the reachability of a TLS-Server using Censor-Scanner
    TLS_CENSOR_DIRECT,
    // Analyzes the censorship between us and an ECHO server using Censor-Scanner
    TLS_CENSOR_ECHO;
}
