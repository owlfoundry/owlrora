use std::{future::Future, time::Duration};

use tokio::time::{Instant, sleep_until};

use crate::protocols::{ProtocolError, ProtocolErrorKind, ResponseMode};

use super::{
    AdmissionContext,
    dispatch::{effective_stream_duration_limit, gateway_error},
};

/// One clock origin for admission, retries, and committed response delivery.
#[derive(Clone, Copy, Debug)]
pub(super) struct RequestLifetime {
    pub precommit: Instant,
    pub terminal: Instant,
}

impl RequestLifetime {
    pub fn new(
        admission: &AdmissionContext,
        mode: ResponseMode,
        started: Instant,
    ) -> Result<Self, ProtocolError> {
        let reliability = admission
            .generation
            .snapshot
            .catalog
            .reliability_policies
            .get(&admission.route.reliability_policy_id)
            .filter(|policy| policy.active)
            .ok_or_else(|| gateway_error(admission, ProtocolErrorKind::RouteUnavailable))?;
        Ok(Self::from_limits(
            started,
            Duration::from_millis(reliability.deadline_policy.overall_timeout_ms),
            (mode != ResponseMode::Json).then(|| {
                Duration::from_secs(u64::from(effective_stream_duration_limit(admission)))
            }),
        ))
    }

    fn from_limits(started: Instant, overall: Duration, streaming: Option<Duration>) -> Self {
        let terminal = started + streaming.unwrap_or(overall);
        Self {
            precommit: (started + overall).min(terminal),
            terminal,
        }
    }

    pub fn constrain(&mut self, deadline: Option<Instant>) {
        if let Some(deadline) = deadline {
            self.precommit = self.precommit.min(deadline);
            self.terminal = self.terminal.min(deadline);
        }
    }
}

/// Unlike polling a ready future inside an expired timeout, expiry wins before any work.
/// The caller retains ownership of values borrowed by `work` after cancellation.
pub(super) async fn before<T>(deadline: Instant, work: impl Future<Output = T>) -> Result<T, ()> {
    if Instant::now() >= deadline {
        return Err(());
    }
    tokio::select! {
        biased;
        () = sleep_until(deadline) => Err(()),
        result = work => Ok(result),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_and_retries_cannot_restart_lifetime() {
        let started = Instant::now();
        let mut lifetime = RequestLifetime::from_limits(
            started,
            Duration::from_secs(10),
            Some(Duration::from_secs(60)),
        );
        assert_eq!(lifetime.precommit, started + Duration::from_secs(10));
        assert_eq!(lifetime.terminal, started + Duration::from_secs(60));
        lifetime.constrain(Some(started + Duration::from_secs(40)));
        assert_eq!(lifetime.precommit, started + Duration::from_secs(10));
        assert_eq!(lifetime.terminal, started + Duration::from_secs(40));
        lifetime.constrain(Some(started + Duration::from_secs(2)));
        assert_eq!(lifetime.precommit, lifetime.terminal);
        lifetime.constrain(Some(started + Duration::from_secs(90)));
        assert_eq!(lifetime.terminal, started + Duration::from_secs(2));
    }

    #[tokio::test]
    async fn expired_lifetime_does_not_poll_ready_work() {
        let mut polled = false;
        let result = before(Instant::now() - Duration::from_secs(1), async {
            polled = true;
        })
        .await;
        assert!(result.is_err());
        assert!(!polled);
    }
}
