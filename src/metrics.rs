use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue};
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use prometheus_client::registry::Registry;

#[derive(Debug, Clone)]
pub struct Metrics {
    active_challenges: Gauge,
    challenge_events: Family<ChallengeEventLabels, Counter>,
    subjective_safe_head: Gauge,
    safe_head: Gauge,
    latest_input_block: Gauge,
    total_commitments_stored: Counter,
    total_input_storage: Counter,
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

        let subjective_safe_head = Gauge::default();
        registry.register(
            "subjective_safe_head",
            "Latest subjective safe head recorded",
            subjective_safe_head.clone(),
        );

        let safe_head = Gauge::default();
        registry.register("safe_head", "Latest safe head recorded", safe_head.clone());

        let latest_input_block = Gauge::default();
        registry.register(
            "latest_input_block",
            "Latest block at which a commitment was stored",
            latest_input_block.clone(),
        );

        let total_commitments_stored = Counter::default();
        registry.register(
            "total_commitments_stored",
            "Total number of commitments stored",
            total_commitments_stored.clone(),
        );

        let total_input_storage = Counter::default();
        registry.register(
            "total_input_storage",
            "Total number of input bytes stored",
            total_input_storage.clone(),
        );

        Self {
            active_challenges,
            challenge_events,
            subjective_safe_head,
            safe_head,
            latest_input_block,
            total_commitments_stored,
            total_input_storage,
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

    pub fn set_subjective_safe_head(&self, block: u64) {
        self.subjective_safe_head.set(block as i64);
    }

    pub fn set_safe_head(&self, block: u64) {
        self.safe_head.set(block as i64);
    }

    pub fn set_latest_input_block(&self, block: u64) {
        self.latest_input_block.set(block as i64);
    }

    pub fn record_commitment_stored(&self, size: usize) {
        self.total_commitments_stored.inc();
        self.total_input_storage.inc_by(size as u64);
    }
}
