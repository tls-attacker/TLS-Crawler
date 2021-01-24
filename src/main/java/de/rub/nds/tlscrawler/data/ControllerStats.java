/**
 * TLS Crawler
 * <p>
 * Licensed under Apache 2.0
 * <p>
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.data;

import java.time.Instant;

/**
 * Implementation of the master stats interface.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class ControllerStats implements IControllerStats {
    private final long totalTasks;
    private final long finishedTasks;
    private final Instant earliestCompletionTimestamp;
    private final Instant earliestCreatedTimestamp;

    public ControllerStats(long totalTasks, long finishedTasks, Instant earliestCompletionTimestamp, Instant earliestCreatedTimestamp) {
        this.totalTasks = totalTasks;
        this.finishedTasks = finishedTasks;
        this.earliestCompletionTimestamp = earliestCompletionTimestamp;
        this.earliestCreatedTimestamp = earliestCreatedTimestamp;
    }

    /**
     * @param stats The stats to copy.
     * @return A threadsafe master stats copy.
     */
    public static ControllerStats copyFrom(IControllerStats stats) {
        if (stats == null) {
            throw new IllegalArgumentException("'stats' must not be null.");
        }

        return new ControllerStats(stats.getTotalTasks(),
            stats.getFinishedTasks(),
            stats.getEarliestCompletionTimestamp(),
            stats.getEarliestCreatedTimestamp());
    }

    @Override
    public long getTotalTasks() {
        return this.totalTasks;
    }

    @Override
    public long getFinishedTasks() {
        return this.finishedTasks;
    }

    @Override
    public Instant getEarliestCompletionTimestamp() {
        return this.earliestCompletionTimestamp;
    }

    @Override
    public Instant getEarliestCreatedTimestamp() {
        return this.earliestCreatedTimestamp;
    }
}