// Thin entry point. Behavior branches on argv[0] inside run(), exactly like the
// C original (which hard-links ssss-split -> ssss-combine).
fn main() {
    ssss::run();
}
