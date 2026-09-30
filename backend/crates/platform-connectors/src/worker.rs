//! Background sync scheduler: runs every configured job on a fixed cadence.

use std::sync::Arc;
use std::time::Duration;

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
            let slug = job.source.descriptor().slug.as_str().to_owned();
            let outcome = self.pipeline.run_sync(job).await;
            if let Err(err) = &outcome {
                tracing::warn!(connector = %slug, error = %err, "sync failed; will retry next tick");
            }
            results.push((slug, outcome));
        }
        results
    }

    /// Background loop. First tick fires immediately, then every `interval`.
    pub async fn run(self, interval: Duration) {
        let mut timer = tokio::time::interval(interval);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            timer.tick().await;
            let results = self.tick().await;
            let ok = results.iter().filter(|(_, r)| r.is_ok()).count();
            tracing::info!(total = results.len(), ok, "sync tick complete");
        }
    }
}
