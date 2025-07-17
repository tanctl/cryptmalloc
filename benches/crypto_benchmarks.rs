use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use cryptmalloc::types::encrypted::EncryptedUint8;
use cryptmalloc::{SecurityLevel, TfheContext};

fn key_generation_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("tfhe_key_generation");

    for level in [
        SecurityLevel::Performance,
        SecurityLevel::Balanced,
        SecurityLevel::Secure,
    ] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{level:?}")),
            &level,
            |b, lvl| {
                b.iter(|| {
                    let ctx = TfheContext::with_security_level(*lvl).expect("context");
                    criterion::black_box(ctx);
                });
            },
        );
    }

    group.finish();
}

fn addition_comparison_benchmarks(c: &mut Criterion) {
    let context = TfheContext::with_security_level(SecurityLevel::Balanced).expect("context");
    let lhs_enc = EncryptedUint8::encrypt(120, &context).expect("encrypt lhs");
    let rhs_enc = EncryptedUint8::encrypt(5, &context).expect("encrypt rhs");
    let lhs_plain: u8 = 120;
    let rhs_plain: u8 = 5;

    let mut group = c.benchmark_group("addition_comparison_u8");
    group.bench_function("encrypted_wrapping_add", |b| {
        b.iter(|| {
            let sum = lhs_enc.wrapping_add(&rhs_enc).expect("add");
            let clear: u8 = sum.decrypt().expect("decrypt");
            criterion::black_box(clear)
        });
    });

    group.bench_function("plaintext_wrapping_add", |b| {
        b.iter(|| {
            let clear = lhs_plain.wrapping_add(rhs_plain);
            criterion::black_box(clear)
        });
    });

    group.finish();
}

criterion_group!(
    crypto,
    key_generation_benchmarks,
    addition_comparison_benchmarks
);
criterion_main!(crypto);
