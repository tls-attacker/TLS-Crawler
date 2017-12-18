/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.data.ISlaveStats;

/**
 * Interface for TLS-Crawler slaves.
 * It may very likely change in the near future as of 27/11/17.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public interface ITlsCrawlerSlave {

    /**
     * Starts the slave. Implementations should not pull tasks before this method has been called.
     */
    void start();

    /**
     * Provides information about the work of this slave instance.
     *
     * @return An object implementing the slave stats interface.
     */
    ISlaveStats getStats();
}