/* Pinned-stock telemetry formatting/aggregation, pending integration.
 * Stats additions wrap u64/u32 as stock. ktime-style ms conversion is signed.
 * Window label is the last eligible CPU's index, not a global synchronized index.
 */
static const char *const erofs_recovered_sizes[5] = {"16", "128", "256", "512", "512+"};
static const char *const erofs_recovered_ranges[5] = {"1", "5", "10", "50", "50+"};

static unsigned long long erofs_recovered_ms(u64 value)
{
	return (u64)((s64)value / 1000000);
}

static struct latency_stats erofs_recovered_daily_total(struct erofs_iostat *io,
		unsigned int category, unsigned int group)
{
	struct latency_stats total = {0};
	struct erofs_iostat_stats *stats;
	struct latency_stats *value;
	unsigned int cpu;

	for_each_possible_cpu(cpu) {
		stats = per_cpu_ptr(io->stats, cpu);
		value = group == 0 ? &stats->daily_stats[category] : group == 1 ?
			&stats->daily_ab_stats[category] : &stats->delay_stats[category];
		total.sum_lat += value->sum_lat;
		total.peak_lat = max(total.peak_lat, value->peak_lat);
		total.bio_cnt += value->bio_cnt;
	}
	return total;
}

ssize_t erofs_iostat_daily_latency_show(struct erofs_sb_info *sbi, char *buffer)
{
	struct erofs_iostat *io = sbi->iostat;
	struct latency_stats total;
	ssize_t length;
	unsigned int category;

	if (!io || !io->iostat_enable)
		return sysfs_emit(buffer, "I/O stats not available\n");
	length = sysfs_emit_at(buffer, 0, "Normal:\n%-12s %-16s %-16s %-16s\n",
		"Size(k)", "Sum(ms)", "Count", "Peak(ms)");
	for (category = 0; category < 5; category++) {
		total = erofs_recovered_daily_total(io, category, 0);
		length += sysfs_emit_at(buffer, length, "%-12s %-16llu %-16u %-16llu\n",
			erofs_recovered_sizes[category], erofs_recovered_ms(total.sum_lat),
			total.bio_cnt, erofs_recovered_ms(total.peak_lat));
	}
	length += sysfs_emit_at(buffer, length, "\nAbnormal:\n%-12s %-16s %-16s %-16s %-16s\n",
		"Size(k)", "Sum(ms)", "Count", "Peak(ms)", "Threshold(ms)");
	for (category = 0; category < 5; category++) {
		total = erofs_recovered_daily_total(io, category, 1);
		length += sysfs_emit_at(buffer, length, "%-12s %-16llu %-16u %-16llu %-16lu\n",
			erofs_recovered_sizes[category], erofs_recovered_ms(total.sum_lat),
			total.bio_cnt, erofs_recovered_ms(total.peak_lat),
			(unsigned long)(io->latency_threshold_ns[category] / 1000000));
	}
	length += sysfs_emit_at(buffer, length, "\nDelay:\n%-10s %-16s %-11s %-16s\n",
		"Range(ms)", "Sum(ms)", "Count", "Peak(ms)");
	for (category = 0; category < 5; category++) {
		total = erofs_recovered_daily_total(io, category, 2);
		length += sysfs_emit_at(buffer, length, "%-10s %-16llu %-11u %-16llu\n",
			erofs_recovered_ranges[category], erofs_recovered_ms(total.sum_lat),
			total.bio_cnt, erofs_recovered_ms(total.peak_lat));
	}
	return length;
}

static struct latency_stats erofs_recovered_window_total(struct erofs_iostat *io,
		unsigned int category, bool abnormal, bool previous, u64 now,
		unsigned int *label)
{
	struct latency_stats total = {0};
	struct erofs_iostat_stats *stats;
	struct latency_stats *value;
	u64 age_limit = io->window_period_ns * (previous ? 3 : 2);
	unsigned int cpu, index;

	for_each_possible_cpu(cpu) {
		stats = per_cpu_ptr(io->stats, cpu);
		if ((u64)(now - stats->current_window_start) > age_limit)
			continue;
		index = (previous ? ~stats->current_window_idx : stats->current_window_idx) & 1;
		*label = index;
		value = abnormal ? &stats->window_ab_stats[index * 5 + category] :
			&stats->window_stats[index * 5 + category];
		total.sum_lat += value->sum_lat;
		total.peak_lat = max(total.peak_lat, value->peak_lat);
		total.bio_cnt += value->bio_cnt;
	}
	return total;
}

ssize_t erofs_iostat_window_latency_show(struct erofs_sb_info *sbi, char *buffer)
{
	struct erofs_iostat *io = sbi->iostat;
	struct latency_stats total;
	u64 now = ktime_get();
	ssize_t length;
	unsigned int category, previous, label = 0;

	if (!io || !io->iostat_enable)
		return sysfs_emit(buffer, "I/O stats not available\n");
	length = sysfs_emit_at(buffer, 0, "Normal:\n%-8s %-12s %-16s %-16s %-16s\n",
		"Window", "Size(k)", "Sum(ms)", "Count", "Peak(ms)");
	for (previous = 0; previous < 2; previous++)
		for (category = 0; category < 5; category++) {
			total = erofs_recovered_window_total(io, category, false, previous, now, &label);
			if (total.bio_cnt)
				length += sysfs_emit_at(buffer, length, "%-8d %-12s %-16llu %-16u %-16llu\n",
					(int)label, erofs_recovered_sizes[category], erofs_recovered_ms(total.sum_lat),
					total.bio_cnt, erofs_recovered_ms(total.peak_lat));
		}
	length += sysfs_emit_at(buffer, length, "\nAbnormal:\n%-8s %-12s %-16s %-16s %-16s %-16s\n",
		"Window", "Size", "Sum(ms)", "Count", "Peak(ms)", "Threshold(ms)");
	for (previous = 0; previous < 2; previous++)
		for (category = 0; category < 5; category++) {
			total = erofs_recovered_window_total(io, category, true, previous, now, &label);
			if (total.bio_cnt)
				length += sysfs_emit_at(buffer, length, "%-8d %-12s %-16llu %-16u %-16llu %-16lu\n",
					(int)label, erofs_recovered_sizes[category], erofs_recovered_ms(total.sum_lat),
					total.bio_cnt, erofs_recovered_ms(total.peak_lat),
					(unsigned long)(io->latency_threshold_ns[category] / 1000000));
		}
	return length;
}
