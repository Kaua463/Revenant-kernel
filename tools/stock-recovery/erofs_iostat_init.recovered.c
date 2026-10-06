/* Semantic reconstruction for the hash-pinned DyperOS 3.0.304 stock.
 * Analysis only: intentionally preserves the stock allocation-failure dangling
 * sbi->iostat value. An installable implementation must review/unwind lifetime;
 * do not copy this failure path into production merely to match the binary.
 */
int erofs_init_iostat(struct erofs_sb_info *sbi)
{
	struct erofs_iostat_stats *stats;
	unsigned int cpu, category;

	sbi->iostat = kzalloc(sizeof(*sbi->iostat), GFP_KERNEL);
	if (!sbi->iostat)
		return -ENOMEM;
	sbi->iostat->iostat_enable = false;
	sbi->iostat->window_period_ns = 60000000000ULL;
	for (category = 0; category < 5; category++)
		sbi->iostat->latency_threshold_ns[category] = 100000000ULL;
	sbi->iostat->stats = alloc_percpu(struct erofs_iostat_stats);
	if (!sbi->iostat->stats) {
		kfree(sbi->iostat);
		/* Stock does not clear sbi->iostat here. */
		return -ENOMEM;
	}
	for_each_possible_cpu(cpu) {
		stats = per_cpu_ptr(sbi->iostat->stats, cpu);
		stats->current_window_idx = 0;
		stats->current_window_start = ktime_get();
		memset(stats->window_stats, 0, sizeof(stats->window_stats));
		memset(stats->window_ab_stats, 0, sizeof(stats->window_ab_stats));
		memset(stats->daily_stats, 0, sizeof(stats->daily_stats));
		memset(stats->daily_ab_stats, 0, sizeof(stats->daily_ab_stats));
		memset(stats->delay_stats, 0, sizeof(stats->delay_stats));
	}
	return 0;
}
