use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use cryptmalloc::allocator::block::EncryptedMemoryBlock;
use cryptmalloc::types::structures::EncryptedSize;
use cryptmalloc::TfheContext;

fn bench_block_operations(c: &mut Criterion) {
    let context = TfheContext::balanced().expect("context");

    c.bench_function("encrypted_block_create", |b| {
        b.iter(|| {
            let block =
                EncryptedMemoryBlock::with_layout(&context, 0x1000, 1024, 1).expect("create block");
            criterion::black_box(block);
        });
    });

    c.bench_function("encrypted_block_split", |b| {
        b.iter(|| {
            let mut block =
                EncryptedMemoryBlock::with_layout(&context, 0x2000, 4096, 2).expect("create block");
            let split = EncryptedSize::encrypt(1024, &context).expect("encrypt split");
            let new_block = block
                .split_block(split, 3, 0x2000 + u64::from(1024))
                .expect("split block");
            criterion::black_box((block, new_block));
        });
    });

    c.bench_function("plaintext_block_split", |b| {
        b.iter(|| {
            let mut size = 4096u32;
            let split = 512u32;
            if size >= split {
                size -= split;
            }
            criterion::black_box((size, split));
        });
    });

    let mut group = c.benchmark_group("encrypted_block_merge");
    for &sz in &[512u32, 1024, 2048] {
        group.bench_with_input(BenchmarkId::from_parameter(sz), &sz, |b, &size_val| {
            b.iter(|| {
                let left_block = EncryptedMemoryBlock::with_layout(&context, 0x4000, size_val, 5)
                    .expect("create left block");
                let right_block = EncryptedMemoryBlock::with_layout(
                    &context,
                    0x4000 + u64::from(size_val),
                    size_val,
                    6,
                )
                .expect("create right block");
                let merged =
                    EncryptedMemoryBlock::merge_blocks(left_block, right_block).expect("merge");
                criterion::black_box(merged);
            });
        });
    }
    group.finish();
}

criterion_group!(block_benches, bench_block_operations);
criterion_main!(block_benches);
