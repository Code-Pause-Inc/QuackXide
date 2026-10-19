//! Background sync scheduler: runs every configured job on a fixed cadence.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use crate::pipeline::{EnclavePipeline, PipelineError, SyncJob, SyncReport};

pub struct SyncScheduler {
    pipeline: Arc<EnclavePipeline>,
    jobs: Vec<SyncJob>,
}

impl SyncScheduler {
    pub fn new(pipeline: Arc<EnclavePipeline>, jobs: Vec<SyncJob>) -> Self {
        Self { pipeline, jobs }
    }

    /// Run every job once. A failing job never aborts its siblings.
    pub async fn tick(&self) -> Vec<(String, Result<SyncReport, PipelineError>)> {
        let mut results = Vec::with_capacity(self.jobs.len());
        for job in &self.jobs {
            results.push(self.sync(job).await);
        }
        results
    }

    /// Background loop. First tick fires immediately, then every `interval`,
    /// until `stop` turns true. A sync that has started runs to its commit;
    /// stopping only skips the jobs not yet started.
    pub async fn run(self, interval: Duration, mut stop: watch::Receiver<bool>) {
        let mut timer = tokio::time::interval(interval);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                _ = stop.wait_for(|stop| *stop) => break,
                _ = timer.tick() => {}
            }
            let mut results = Vec::with_capacity(self.jobs.len());
            for job in &self.jobs {
                if *stop.borrow() {
                    break;
                }
                results.push(self.sync(job).await);
            }
            let ok = results.iter().filter(|(_, r)| r.is_ok()).count();
            tracing::info!(total = results.len(), ok, "sync tick complete");
        }
        tracing::info!("scheduler stopped");
    }

    async fn sync(&self, job: &SyncJob) -> (String, Result<SyncReport, PipelineError>) {
        let slug = job.source.descriptor().slug.as_str().to_owned();
        let outcome = self.pipeline.run_sync(job).await;
        if let Err(err) = &outcome {
            tracing::warn!(connector = %slug, error = %err, "sync failed; will retry next tick");
        }
        (slug, outcome)
    }
}
