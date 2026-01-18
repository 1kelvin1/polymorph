//! JSON output example

fn main() {
    let report = serde_json::json!({
        "file": "malware.exe",
        "detections": 5,
        "risk_score": 85,
        "verdict": "CRITICAL"
    });
    
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}
