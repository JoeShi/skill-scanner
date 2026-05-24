use skill_scanner_core::Severity;

// C3 amendment regression: Severity::priority() must return P0 > P1 > P2
#[test]
fn severity_priority_ordering() {
    assert!(
        Severity::P0.priority() > Severity::P1.priority(),
        "P0 must have higher priority than P1"
    );
    assert!(
        Severity::P1.priority() > Severity::P2.priority(),
        "P1 must have higher priority than P2"
    );
    assert!(
        Severity::P0.priority() > Severity::P2.priority(),
        "P0 must have higher priority than P2 (transitivity)"
    );
}
