/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.orchestration;

import de.rub.nds.tlscrawler.data.IScanTask;

import java.util.LinkedList;
import java.util.List;

/**
 * Simplest implementation of an orchestration provider.
 * Stores scan tasks in memory.
 * Intended for testing purposes: Single instance and no persistence.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class InMemoryOrchestrationProvider implements IOrchestrationProvider {
    private List<IScanTask> tasks = new LinkedList<IScanTask>();

    public IScanTask getScanTask() {
        return tasks.isEmpty() ? null : tasks.get(0);
    }

    public void addScanTask(IScanTask task) {
        this.tasks.add(task);
    }
}