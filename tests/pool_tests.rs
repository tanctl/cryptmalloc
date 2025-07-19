use cryptmalloc::{PoolError, SecurityLevel, TfheContext, VirtualMemoryPool};
use std::sync::Arc;
use std::thread;

#[test]
fn pool_initialization_and_stats() {
    let context = TfheContext::with_security_level(SecurityLevel::Performance).expect("context");
    let pool = VirtualMemoryPool::builder(context.clone())
        .pool_bytes(8 * 1024)
        .base_address(0x2000)
        .min_alignment(16)
        .build()
        .expect("build pool");

    pool.verify_integrity().expect("integrity");
    let stats = pool.stats().expect("stats");
    assert_eq!(stats.total.decrypt().expect("decrypt total"), 8 * 1024);
    assert_eq!(stats.used.decrypt().expect("decrypt used"), 0);
    assert!((stats.utilization - 0.0).abs() < f64::EPSILON);
    assert!(stats.fragmentation >= 0.0);

    let display = format!("{pool}");
    assert!(display.contains("pool total="));
}

#[test]
fn pool_allocation_and_release() {
    let context = TfheContext::with_security_level(SecurityLevel::Performance).expect("context");
    let pool = VirtualMemoryPool::builder(context.clone())
        .pool_bytes(16 * 1024)
        .base_address(0x4000)
        .min_alignment(32)
        .build()
        .expect("build pool");

    let block_a = pool.allocate_block(1024, 64).expect("allocate block a");
    pool.record_access(block_a).expect("record a");
    let block_b = pool.allocate_block(2048, 64).expect("allocate block b");
    pool.record_access(block_b).expect("record b");

    let stats = pool.stats().expect("stats");
    assert_eq!(stats.used.decrypt().expect("decrypt used"), 1024 + 2048);
    assert_eq!(stats.allocations, 2);
    assert_eq!(stats.access_events, 2);

    pool.release_block(block_a).expect("release a");
    pool.release_block(block_b).expect("release b");
    let stats_after = pool.stats().expect("stats after");
    assert_eq!(stats_after.used.decrypt().expect("decrypt"), 0);
    assert_eq!(stats_after.deallocations, 2);
}

#[test]
fn pool_alignment_reuse_creates_head_padding() {
    let context = TfheContext::with_security_level(SecurityLevel::Performance).expect("context");
    let pool = VirtualMemoryPool::builder(context.clone())
        .pool_bytes(4096)
        .base_address(0x2008)
        .min_alignment(8)
        .build()
        .expect("build pool");

    let handle = pool.allocate_block(512, 8).expect("allocate initial");
    pool.release_block(handle).expect("release initial");

    let aligned_handle = pool
        .allocate_block(256, 256)
        .expect("allocate aligned block");

    let snapshot: Vec<_> = pool.block_snapshot().expect("snapshot").collect();

    let allocated = snapshot
        .iter()
        .find(|view| view.handle == aligned_handle && view.allocated)
        .expect("allocated block");

    let address = allocated.address.decrypt().expect("decrypt address");
    assert_eq!(address % 256, 0);

    let head_padding = snapshot
        .iter()
        .find(|view| !view.allocated && view.handle != aligned_handle)
        .expect("head padding block");
    assert_eq!(head_padding.size.decrypt().expect("padding size"), 248);
}

#[test]
fn pool_concurrent_stress() {
    let context = TfheContext::balanced().expect("context");
    let pool = Arc::new(
        VirtualMemoryPool::builder(context.clone())
            .pool_bytes(32 * 1024)
            .base_address(0x8000)
            .min_alignment(16)
            .build()
            .expect("build pool"),
    );

    let mut handles = Vec::new();
    for _ in 0..4 {
        let pool_clone = Arc::clone(&pool);
        handles.push(thread::spawn(move || -> Result<(), PoolError> {
            for size in [256u32, 512, 768] {
                let handle = pool_clone.allocate_block(size, 16)?;
                pool_clone.record_access(handle)?;
                pool_clone.release_block(handle)?;
            }
            Ok(())
        }));
    }

    for handle in handles {
        handle.join().expect("thread join").expect("thread success");
    }

    let stats = pool.stats().expect("stats");
    assert_eq!(stats.used.decrypt().expect("decrypt"), 0);
    assert_eq!(stats.deallocations, 4 * 3);
    assert!(stats.access_events >= 12);
}

#[test]
fn pool_rebuild_box_links_restores_links() {
    let context = TfheContext::with_security_level(SecurityLevel::Performance).expect("context");
    let pool = VirtualMemoryPool::builder(context.clone())
        .pool_bytes(4 * 1024)
        .base_address(0x3000)
        .min_alignment(16)
        .build()
        .expect("build pool");

    let block_a = pool.allocate_block(64, 16).expect("alloc a");
    let _block_b = pool.allocate_block(64, 16).expect("alloc b");
    pool.release_block(block_a).expect("release a");
    pool.rebuild_box_links().expect("rebuild");
    let snapshot = pool.block_snapshot().expect("snapshot");
    for view in snapshot {
        let block = pool.snapshot_block(view.handle).expect("inspect");
        assert!(block.is_some());
    }
}
