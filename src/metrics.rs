use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue};
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use prometheus_client::registry::Registry;

#[derive(Debug, Clone)]
pub struct Metrics {
    active_challenges: Gauge,
    challenge_events: Family<ChallengeEventLabels, Counter>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ChallengeEventLabels {
    event: ChallengeEventType,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelValue)]
enum ChallengeEventType {
    Resolved,
    Expired,
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        let challenge_events = Family::default();
        registry.register(
            "challenge_events",
            "Events emitted by the challenge contract when a challenge is expired or resolved",
            challenge_events.clone(),
        );

        let active_challenges = Gauge::default();
        registry.register(
            "active_challenges",
            "Number of active challenges",
            active_challenges.clone(),
        );

        Self {
            active_challenges,
            challenge_events,
        }
    }

    pub fn record_active_challenge(&self) {
        self.active_challenges.inc();
    }

    pub fn record_resolved_challenge(&self) {
        self.active_challenges.dec();
        self.challenge_events
            .get_or_create(&ChallengeEventLabels {
                event: ChallengeEventType::Resolved,
            })
            .inc();
    }

    pub fn record_expired_challenge(&self) {
        self.active_challenges.dec();
        self.challenge_events
            .get_or_create(&ChallengeEventLabels {
                event: ChallengeEventType::Expired,
            })
            .inc();
    }
}
