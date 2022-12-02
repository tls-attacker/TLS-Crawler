/*
 * TLS-Crawler is able to perform large scale
 * analyses on censorship.
 *
 * Copyright 2018-2022
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlscrawler.orchestration;

import de.rub.nds.tlscrawler.data.ScanJob;

@FunctionalInterface
public interface ScanJobConsumer {

    void consumeScanJob(ScanJob scanJob, long deliveryTag);
}
