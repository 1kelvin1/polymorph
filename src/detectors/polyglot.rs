use super::{Detection, DetectionCategory, Severity};

pub fn scan_entropy_anomalies(data: &[u8], detections: &mut Vec<Detection>) {
    let chunk_size = 4096;
    let mut high_entropy_chunks = 0;

    for (i, chunk) in data.chunks(chunk_size).enumerate() {
        let entropy = calculate_entropy(chunk);
        
        if entropy > 7.2 {
            high_entropy_chunks += 1;
            
            if high_entropy_chunks == 1 {
                detections.push(Detection {
                    category: DetectionCategory::StringObfuscation,
                    severity: Severity::Medium,
                    description: format!("High entropy section (entropy: {:.2}), possible encryption", entropy),
                    offset: Some(i * chunk_size),
                });
            }
        }
    }

    if high_entropy_chunks > 5 {
        detections.push(Detection {
            category: DetectionCategory::StringObfuscation,
            severity: Severity::High,
            description: format!("Multiple high-entropy sections ({}), likely packed/encrypted payload", high_entropy_chunks),
            offset: None,
        });
    }
}

fn calculate_entropy(data: &[u8]) -> f64 {
    let mut frequencies = [0u32; 256];
    
    for &byte in data {
        frequencies[byte as usize] += 1;
    }
    
    let len = data.len() as f64;
    let mut entropy = 0.0;
    
    for &freq in frequencies.iter() {
        if freq > 0 {
            let probability = freq as f64 / len;
            entropy -= probability * probability.log2();
        }
    }
    
    entropy
}
