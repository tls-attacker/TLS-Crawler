/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.orchestration;

import de.rub.nds.tlscrawler.data.ScanJob;

@FunctionalInterface
public interface DoneNotificationConsumer {

    void consumeDoneNotification(String consumerTag, ScanJob scanJob);
}
