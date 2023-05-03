use criterion::{black_box, criterion_group, criterion_main, Criterion};

use blake3_lamport_signatures::merkle;

fn criterion_benchmark(c: &mut Criterion) {
    let to_sign = vec![0u8; 1000000];
    let to_sign: &[u8] = &to_sign;
    let mut private_key = merkle::PrivateKey::generate(100000).unwrap();
    c.bench_function("signature", |b| {
        b.iter(|| private_key.sign(black_box(to_sign)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
