use std::{env, time::Duration};

use owlrora_server::{
    adapters::coordinator::{
        BudgetGrantSide, CoordinatorError, CoordinatorRecoveryInstall, PairedBudgetGrantRequest,
        PolicyCandidate, PolicyCoordinatorConfig, PolicyReference, RedisCoordinator,
        TargetHealthCategory, TargetHealthSummary,
    },
    domain::{OrganizationId, PolicyKind},
};
use uuid::Uuid;

async fn coordinator() -> Option<RedisCoordinator> {
    let url = env::var("OWLRORA_TEST_REDIS_URL").ok()?;
    let url = url::Url::parse(&url).expect("valid OWLRORA_TEST_REDIS_URL");
    Some(
        RedisCoordinator::connect(&url, 4, Duration::from_secs(2), Duration::from_secs(2))
            .await
            .expect("connect to test Redis"),
    )
}

fn budget_candidate(organization_id: OrganizationId) -> PolicyCandidate {
    let version_id = Uuid::now_v7();
    PolicyCandidate {
        organization_id,
        kind: PolicyKind::GatewayKeyBudget,
        policy_id: Uuid::now_v7(),
        desired_epoch: Uuid::now_v7().to_string(),
        desired_version_id: version_id,
        desired_generation: 1,
        desired_recovery_generation: 0,
        fence: Uuid::now_v7(),
        config: PolicyCoordinatorConfig::Budget {
            version_id,
            mode: "enforce".to_owned(),
            limit_cost_nanos: "1000".to_owned(),
            max_slice_nanos: "100".to_owned(),
            grant_seconds: 30,
        },
    }
}

fn reference(candidate: &PolicyCandidate) -> PolicyReference {
    PolicyReference {
        organization_id: candidate.organization_id,
        kind: candidate.kind,
        policy_id: candidate.policy_id,
        version_id: candidate.desired_version_id,
        epoch: candidate.desired_epoch.clone(),
        generation: candidate.desired_generation,
        recovery_generation: candidate.desired_recovery_generation,
    }
}

async fn activate(coordinator: &RedisCoordinator, candidate: &PolicyCandidate) {
    coordinator.stage_policy(candidate).await.expect("stage");
    coordinator.arm_policy(candidate).await.expect("arm");
    coordinator
        .activate_policy(candidate)
        .await
        .expect("activate");
}

#[tokio::test]
async fn paired_budget_grants_are_fenced_bounded_and_idempotently_returned() {
    let Some(coordinator) = coordinator().await else {
        return;
    };
    let organization_id = OrganizationId::new();
    let candidate = budget_candidate(organization_id);
    activate(&coordinator, &candidate).await;
    let policy = reference(&candidate);
    let request = PairedBudgetGrantRequest {
        organization_id,
        grant_id: Uuid::now_v7(),
        node_instance_id: "redis-integration".to_owned(),
        key: Some(BudgetGrantSide {
            policy: policy.clone(),
            amount_nanos: 100,
        }),
        origin: None,
        requested_ttl: Duration::from_secs(30),
        one_shot: false,
    };
    let first = coordinator
        .grant_budget_allowance(&request)
        .await
        .expect("grant");
    let repeated = coordinator
        .grant_budget_allowance(&request)
        .await
        .expect("idempotent grant");
    assert_eq!(first, repeated);

    coordinator
        .return_budget_allowance(&request, 40, 0)
        .await
        .expect("return unused");
    coordinator
        .return_budget_allowance(&request, 40, 0)
        .await
        .expect("idempotent return");
    assert!(matches!(
        coordinator.return_budget_allowance(&request, 41, 0).await,
        Err(CoordinatorError::Conflict)
    ));

    let fill = PairedBudgetGrantRequest {
        grant_id: Uuid::now_v7(),
        key: Some(BudgetGrantSide {
            policy: policy.clone(),
            amount_nanos: 940,
        }),
        one_shot: true,
        ..request.clone()
    };
    coordinator
        .grant_budget_allowance(&fill)
        .await
        .expect("fill exact remaining limit");
    let denied = PairedBudgetGrantRequest {
        grant_id: Uuid::now_v7(),
        key: Some(BudgetGrantSide {
            policy,
            amount_nanos: 1,
        }),
        one_shot: true,
        ..request
    };
    assert!(matches!(
        coordinator.grant_budget_allowance(&denied).await,
        Err(CoordinatorError::Denied)
    ));
}

async fn assert_binding_specific_target_health(coordinator: &RedisCoordinator, target_id: Uuid) {
    let summary = TargetHealthSummary {
        target_id,
        deployment_id: Uuid::now_v7(),
        endpoint_id: Uuid::now_v7(),
        credential_id: Uuid::now_v7(),
        runtime_revision: 17,
        binding_fingerprint: [29; 32],
        health_epoch: Uuid::now_v7(),
        category: TargetHealthCategory::Healthy,
        cooldown_until_unix_ms: None,
        recovery_started_at_unix_ms: None,
        observed_at_unix_ms: 1_700_000_000_000,
        source_node_id: "probe-node-a".to_owned(),
    };
    assert!(matches!(
        coordinator
            .put_target_health_summary(&summary, "probe-node-b", Duration::from_secs(1))
            .await,
        Err(CoordinatorError::Conflict)
    ));
    coordinator
        .put_target_health_summary(&summary, "probe-node-a", Duration::from_secs(1))
        .await
        .expect("publish target health");
    let (stored_summary, remaining_ttl) = coordinator
        .get_target_health_summary(target_id, &[29; 32])
        .await
        .expect("read target health");
    assert_eq!(stored_summary, summary);
    assert!(!remaining_ttl.is_zero() && remaining_ttl <= Duration::from_secs(1));

    let newer_binding_summary = TargetHealthSummary {
        binding_fingerprint: [30; 32],
        health_epoch: Uuid::now_v7(),
        category: TargetHealthCategory::Open,
        source_node_id: "probe-node-b".to_owned(),
        ..summary.clone()
    };
    coordinator
        .put_target_health_summary(
            &newer_binding_summary,
            "probe-node-b",
            Duration::from_secs(1),
        )
        .await
        .expect("publish independently fenced binding health");
    assert_eq!(
        coordinator
            .get_target_health_summary(target_id, &[30; 32])
            .await
            .expect("read new binding health")
            .0,
        newer_binding_summary
    );
    assert_eq!(
        coordinator
            .get_target_health_summary(target_id, &[29; 32])
            .await
            .expect("old binding remains isolated")
            .0,
        summary
    );
}

#[tokio::test]
async fn target_probe_leases_are_single_owner_and_health_is_ttl_bound() {
    let Some(coordinator) = coordinator().await else {
        return;
    };
    let target_id = Uuid::now_v7();
    assert!(
        coordinator
            .try_acquire_target_probe_lease(
                target_id,
                &[29; 32],
                "probe-node-a",
                Duration::from_millis(100),
            )
            .await
            .expect("first probe lease")
    );
    assert!(
        !coordinator
            .try_acquire_target_probe_lease(
                target_id,
                &[29; 32],
                "probe-node-b",
                Duration::from_millis(100),
            )
            .await
            .expect("second probe lease is denied")
    );
    assert!(
        coordinator
            .try_acquire_target_probe_lease(
                target_id,
                &[30; 32],
                "probe-node-b",
                Duration::from_secs(1),
            )
            .await
            .expect("a new target binding is independently fenced")
    );

    assert_binding_specific_target_health(&coordinator, target_id).await;

    tokio::time::sleep(Duration::from_millis(125)).await;
    assert!(
        coordinator
            .try_acquire_target_probe_lease(
                target_id,
                &[29; 32],
                "probe-node-b",
                Duration::from_millis(100),
            )
            .await
            .expect("probe lease takeover")
    );
}

#[tokio::test]
async fn coordinator_recovery_fences_old_grants_and_exposes_only_authorized_allowance() {
    let Some(coordinator) = coordinator().await else {
        return;
    };
    let organization_id = OrganizationId::new();
    let candidate = budget_candidate(organization_id);
    activate(&coordinator, &candidate).await;
    let original = reference(&candidate);
    let recovery_id = Uuid::now_v7();
    let recovery = CoordinatorRecoveryInstall {
        recovery_id,
        organization_id,
        kind: candidate.kind,
        policy_id: candidate.policy_id,
        version_id: candidate.desired_version_id,
        epoch: candidate.desired_epoch.clone(),
        policy_generation: candidate.desired_generation,
        recovery_generation: 1,
        authorized_allowance_nanos: 60,
        limit_cost_nanos: 1_000,
        config: candidate.config.clone(),
    };
    coordinator
        .install_coordinator_recovery(&recovery)
        .await
        .expect("install recovery");
    coordinator
        .install_coordinator_recovery(&recovery)
        .await
        .expect("idempotently reinstall recovery");

    let old_request = PairedBudgetGrantRequest {
        organization_id,
        grant_id: Uuid::now_v7(),
        node_instance_id: "recovery-test-node".to_owned(),
        requested_ttl: Duration::from_secs(10),
        one_shot: true,
        key: Some(BudgetGrantSide {
            policy: original,
            amount_nanos: 1,
        }),
        origin: None,
    };
    assert!(matches!(
        coordinator.grant_budget_allowance(&old_request).await,
        Err(CoordinatorError::Denied)
    ));

    let mut recovered = reference(&candidate);
    recovered.recovery_generation = 1;
    let authorized = PairedBudgetGrantRequest {
        organization_id,
        grant_id: Uuid::now_v7(),
        node_instance_id: "recovery-test-node".to_owned(),
        requested_ttl: Duration::from_secs(10),
        one_shot: true,
        key: Some(BudgetGrantSide {
            policy: recovered.clone(),
            amount_nanos: 60,
        }),
        origin: None,
    };
    coordinator
        .grant_budget_allowance(&authorized)
        .await
        .expect("authorized recovery allowance is available");
    let exhausted = PairedBudgetGrantRequest {
        grant_id: Uuid::now_v7(),
        key: Some(BudgetGrantSide {
            policy: recovered,
            amount_nanos: 1,
        }),
        ..authorized
    };
    assert!(matches!(
        coordinator.grant_budget_allowance(&exhausted).await,
        Err(CoordinatorError::Denied)
    ));

    let mut conflicting = recovery;
    conflicting.authorized_allowance_nanos = 61;
    assert!(matches!(
        coordinator.install_coordinator_recovery(&conflicting).await,
        Err(CoordinatorError::Conflict)
    ));
}

#[tokio::test]
async fn rate_and_concurrency_use_exact_active_generation() {
    let Some(coordinator) = coordinator().await else {
        return;
    };
    let organization_id = OrganizationId::new();
    let version_id = Uuid::now_v7();
    let candidate = PolicyCandidate {
        organization_id,
        kind: PolicyKind::GatewayKeyRequestLimits,
        policy_id: Uuid::now_v7(),
        desired_epoch: Uuid::now_v7().to_string(),
        desired_version_id: version_id,
        desired_generation: 1,
        desired_recovery_generation: 0,
        fence: Uuid::now_v7(),
        config: PolicyCoordinatorConfig::RequestLimits {
            version_id,
            requests_per_minute: 3,
            input_units_per_minute: Some(30),
            grant_mode: "local_grants".to_owned(),
            max_request_tokens: 2,
            grant_seconds: 10,
            concurrency_mode: Some("approximate".to_owned()),
            concurrency_limit: Some(2),
            lease_seconds: None,
            max_stream_seconds: 5,
        },
    };
    activate(&coordinator, &candidate).await;
    let policy = reference(&candidate);
    let rate = coordinator
        .grant_rate_tokens(&policy, Uuid::now_v7(), 2, 20, false)
        .await
        .expect("local rate grant");
    assert_eq!(rate.request_tokens, 2);
    assert_eq!(rate.input_tokens, 20);
    assert!(matches!(
        coordinator
            .grant_rate_tokens(&policy, Uuid::now_v7(), 2, 20, false)
            .await,
        Err(CoordinatorError::Denied)
    ));

    let slots = coordinator
        .grant_approximate_concurrency_slots(&policy, Uuid::now_v7(), 2)
        .await
        .expect("slot grant");
    assert_eq!(slots.slots, 2);
    assert!(matches!(
        coordinator
            .grant_approximate_concurrency_slots(&policy, Uuid::now_v7(), 1)
            .await,
        Err(CoordinatorError::Denied)
    ));

    let mut stale = policy;
    stale.generation = 2;
    assert!(matches!(
        coordinator
            .grant_rate_tokens(&stale, Uuid::now_v7(), 1, 1, false)
            .await,
        Err(CoordinatorError::Conflict)
    ));
}
