/* Stock-derived controls; pending full subsystem integration/lifetime review.
 * Buffers are mutable, as in the stock strim/strsep call paths.
 */
int erofs_iostat_config_parse(struct erofs_sb_info *sbi, char *buffer)
{
	struct erofs_iostat *iostat = sbi->iostat;
	unsigned long long values[6] = {0};
	char *cursor = strim(buffer), *token;
	unsigned int i;

	if (!iostat)
		return -EINVAL;
	if (!cursor)
		return -ENOMEM;
	for (i = 0; i < 6; i++) {
		token = strsep(&cursor, ",");
		if (!token || kstrtoull(token, 10, &values[i]))
			return -EINVAL;
		if (!i && values[0] > 0xffffffffULL)
			return -EINVAL;
	}
	if (cursor)
		return -EINVAL;
	iostat->window_period_ns = values[0] * 1000000000ULL;
	for (i = 0; i < 5; i++)
		iostat->latency_threshold_ns[i] = values[i + 1] * 1000000ULL;
	return 0;
}

int erofs_iostat_daily_stats_reset(struct erofs_sb_info *sbi, char *buffer)
{
	struct erofs_iostat *iostat = sbi->iostat;
	char *trimmed = strim(buffer);
	struct erofs_iostat_stats *stats;
	unsigned int cpu;

	if (!iostat || !iostat->iostat_enable)
		return -ENODEV;
	/* Stock checks only five bytes; it also accepts reset-prefixed strings. */
	if (strncmp(trimmed, "reset", 5))
		return -EINVAL;
	for_each_possible_cpu(cpu) {
		stats = per_cpu_ptr(iostat->stats, cpu);
		memset(stats->daily_stats, 0, sizeof(stats->daily_stats));
		memset(stats->daily_ab_stats, 0, sizeof(stats->daily_ab_stats));
		memset(stats->delay_stats, 0, sizeof(stats->delay_stats));
	}
	return 0;
}

void erofs_iostat_latency_stats_reset(struct erofs_sb_info *sbi)
{
	struct erofs_iostat_stats *stats;
	unsigned int cpu;

	for_each_possible_cpu(cpu) {
		stats = per_cpu_ptr(sbi->iostat->stats, cpu);
		memset(stats->window_stats, 0, sizeof(stats->window_stats));
		memset(stats->window_ab_stats, 0, sizeof(stats->window_ab_stats));
		memset(stats->daily_stats, 0, sizeof(stats->daily_stats));
		memset(stats->daily_ab_stats, 0, sizeof(stats->daily_ab_stats));
		memset(stats->delay_stats, 0, sizeof(stats->delay_stats));
	}
}
