use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::fs;

fn benchmark_scan_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("scan_performance");
    
    for size in [1024, 10240, 102400, 1048576].iter() {
        let test_data = vec![0x41u8; *size]; // 'A' repeated
        
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}KB", size / 1024)),
            size,
            |b, _| {
                b.iter(|| {
                    // Simulate pattern matching
                    black_box(test_data.windows(8).count());
                });
            },
        );
    }
    group.finish();
}

fn benchmark_pattern_matching(c: &mut Criterion) {
    let data = vec![0x41u8; 1048576]; // 1MB
    let pattern = b"MZqFpD";
    
    c.bench_function("pattern_search_1mb", |b| {
        b.iter(|| {
            black_box(
                data.windows(pattern.len())
                    .position(|window| window == pattern)
            );
        });
    });
}

fn benchmark_entropy_calculation(c: &mut Criterion) {
    let data: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
    
    c.bench_function("entropy_4kb", |b| {
        b.iter(|| {
            let mut frequencies = [0u32; 256];
            for &byte in black_box(&data) {
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
            black_box(entropy);
        });
    });
}

criterion_group!(
    benches,
    benchmark_scan_sizes,
    benchmark_pattern_matching,
    benchmark_entropy_calculation
);
criterion_main!(benches);
