/*
 * TLS-Crawler is able to perform large scale
 * analyses on censorship.
 *
 * Copyright 2018-2022
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlscrawler.persistence;

import de.rub.nds.tlscrawler.data.BulkScan;
import de.rub.nds.tlscrawler.data.ScanResult;

/**
 * Persistence provider interface. Exposes methods to write out the different stages of a task to a file/database/api.
 */
public interface IPersistenceProvider {

    void insertScanResult(ScanResult scanResult, String dbName, String collectionName);

    void insertBulkScan(BulkScan bulkScan);

    void updateBulkScan(BulkScan bulkScan);
}
