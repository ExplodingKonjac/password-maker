use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
/// The UI additionally locks on wall-clock heartbeat gaps, including process suspension.
pub fn install(signal: Arc<AtomicBool>, stop: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        let mut previous = std::time::SystemTime::now();
        while !stop.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(500));
            let now = std::time::SystemTime::now();
            if now
                .duration_since(previous)
                .map_or(true, |elapsed| elapsed > std::time::Duration::from_secs(2))
            {
                signal.store(true, Ordering::SeqCst);
            }
            previous = now;
        }
    });
}
