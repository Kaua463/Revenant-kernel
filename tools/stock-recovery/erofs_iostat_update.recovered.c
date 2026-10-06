/* Semantic reconstruction for pinned DyperOS 3.0.304 only.
 * Not installed. Requires stock-equivalent structures and per-CPU lifetime.
 * The odd byte-size bucket boundaries and abnormal maxima deliberately follow
 * the stock instructions; do not silently replace them with cleaner heuristics.
 */
void erofs_iostat_update(struct erofs_sb_info *sbi, struct bio *bio)
{
	struct erofs_iostat *iostat = sbi->iostat;
	struct erofs_iostat_stats *stats;
	struct latency_stats *window, *daily, *ab_window, *ab_daily, *delay;
	u64 elapsed, now;
	u32 bytes, category, latency_category, index;

	if (!iostat->iostat_enable || !bio->android_oem_data1)
		return;
	now = ktime_get();
	elapsed = now - bio->android_oem_data1;
	bytes = bio->bi_iter.bi_size;
	category = ((bytes >> 10) > 16) + ((bytes >> 10) > 128) +
		(bytes > 0x403ff) + (bytes > 0x803ff);
	latency_category = elapsed < 1000000 ? 0 : elapsed < 5000000 ? 1 :
		elapsed < 10000000 ? 2 : elapsed < 50000000 ? 3 : 4;
	stats = get_cpu_ptr(iostat->stats);
	index = stats->current_window_idx;
	if ((u64)(now - stats->current_window_start) > iostat->window_period_ns) {
		stats->current_window_start = now;
		index = (~index) & 1;
		stats->current_window_idx = index;
		memset(&stats->window_stats[index * 5], 0, 5 * sizeof(struct latency_stats));
		memset(&stats->window_ab_stats[index * 5], 0, 5 * sizeof(struct latency_stats));
	}
	/* Stock has a bounds-check trap for a corrupted window index. */
	BUG_ON(index > 1);
	window = &stats->window_stats[index * 5 + category];
	daily = &stats->daily_stats[category];
	window->sum_lat += elapsed;
	window->peak_lat = max(window->peak_lat, elapsed);
	window->bio_cnt++;
	daily->sum_lat += elapsed;
	daily->peak_lat = max(daily->peak_lat, elapsed);
	daily->bio_cnt++;
	if (elapsed > iostat->latency_threshold_ns[category]) {
		ab_window = &stats->window_ab_stats[index * 5 + category];
		ab_daily = &stats->daily_ab_stats[category];
		ab_window->sum_lat += elapsed;
		ab_window->peak_lat = window->peak_lat;
		ab_window->bio_cnt++;
		ab_daily->sum_lat += elapsed;
		ab_daily->peak_lat = daily->peak_lat;
		ab_daily->bio_cnt++;
	}
	delay = &stats->delay_stats[latency_category];
	delay->sum_lat += elapsed;
	delay->peak_lat = max(delay->peak_lat, elapsed);
	delay->bio_cnt++;
	put_cpu_ptr(iostat->stats);
	bio->android_oem_data1 = 0;
}

void erofs_destroy_iostat(struct erofs_sb_info *sbi)
{
	if (!sbi->iostat)
		return;
	if (sbi->iostat->stats)
		free_percpu(sbi->iostat->stats);
	kfree(sbi->iostat);
	sbi->iostat = NULL;
}
