/* Exact stock BTF field types/layouts on ARM64; not a universal-version ABI. */
#ifndef EROFS_RECOVERED_IOSTAT_H
#define EROFS_RECOVERED_IOSTAT_H
#include <linux/percpu.h>
#include <linux/types.h>

struct latency_stats {
	unsigned long sum_lat;
	unsigned long peak_lat;
	unsigned int bio_cnt;
};

struct erofs_iostat_stats {
	unsigned int current_window_idx;
	unsigned long current_window_start;
	struct latency_stats window_stats[10];
	struct latency_stats window_ab_stats[10];
	struct latency_stats daily_stats[5];
	struct latency_stats daily_ab_stats[5];
	struct latency_stats delay_stats[5];
};

struct erofs_iostat {
	bool iostat_enable;
	unsigned long window_period_ns;
	unsigned long latency_threshold_ns[5];
	struct erofs_iostat_stats __percpu *stats;
};

struct erofs_sb_info;
struct bio;
int erofs_init_iostat(struct erofs_sb_info *sbi);
void erofs_destroy_iostat(struct erofs_sb_info *sbi);
void erofs_iostat_update(struct erofs_sb_info *sbi, struct bio *bio);
void erofs_iostat_record_start(struct erofs_sb_info *sbi, struct bio *bio);
int erofs_iostat_config_parse(struct erofs_sb_info *sbi, char *buffer);
int erofs_iostat_daily_stats_reset(struct erofs_sb_info *sbi, char *buffer);
void erofs_iostat_latency_stats_reset(struct erofs_sb_info *sbi);
ssize_t erofs_iostat_daily_latency_show(struct erofs_sb_info *sbi, char *buffer);
ssize_t erofs_iostat_window_latency_show(struct erofs_sb_info *sbi, char *buffer);
#endif
