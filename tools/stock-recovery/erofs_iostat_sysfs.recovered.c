/* Pinned stock sysfs dispatcher reconstruction, not installed.
 * erofs_attr, enums and container layout must match recovered BTF/data objects.
 * Stock permits concurrent updates/resets without an explicit lock here.
 */
static unsigned char *erofs_recovered_struct_ptr(struct erofs_sb_info *sbi,
		int struct_type, int offset)
{
	if (struct_type == 0)
		return (unsigned char *)sbi + offset;
	if (struct_type == 1)
		return (unsigned char *)&sbi->opt + offset;
	if (struct_type == 2)
		return (unsigned char *)sbi->iostat + offset;
	return NULL;
}

static ssize_t erofs_attr_show(struct kobject *kobj, struct attribute *attr,
		char *buf)
{
	struct erofs_sb_info *sbi = container_of(kobj, struct erofs_sb_info, s_kobj);
	struct erofs_attr *a = container_of(attr, struct erofs_attr, attr);
	unsigned char *ptr = erofs_recovered_struct_ptr(sbi, a->struct_type, a->offset);
	struct erofs_iostat *io;

	switch (a->attr_id) {
	case 0:
		return sysfs_emit(buf, "supported\n");
	case 1:
		return ptr ? sysfs_emit(buf, "%u\n", *(unsigned int *)ptr) : 0;
	case 2:
		return ptr ? sysfs_emit(buf, "%d\n", *(bool *)ptr) : 0;
	case 3:
		if (!ptr)
			return 0;
		io = sbi->iostat;
		return sysfs_emit(buf, "%lu,%lu,%lu,%lu,%lu,%lu\n",
			(unsigned long)(io->window_period_ns / 1000000000),
			(unsigned long)(io->latency_threshold_ns[0] / 1000000),
			(unsigned long)(io->latency_threshold_ns[1] / 1000000),
			(unsigned long)(io->latency_threshold_ns[2] / 1000000),
			(unsigned long)(io->latency_threshold_ns[3] / 1000000),
			(unsigned long)(io->latency_threshold_ns[4] / 1000000));
	case 4:
		return ptr ? erofs_iostat_window_latency_show(sbi, buf) : 0;
	case 5:
		return ptr ? erofs_iostat_daily_latency_show(sbi, buf) : 0;
	}
	return 0;
}

static ssize_t erofs_attr_store(struct kobject *kobj, struct attribute *attr,
		const char *buf, size_t len)
{
	struct erofs_sb_info *sbi = container_of(kobj, struct erofs_sb_info, s_kobj);
	struct erofs_attr *a = container_of(attr, struct erofs_attr, attr);
	unsigned char *ptr = erofs_recovered_struct_ptr(sbi, a->struct_type, a->offset);
	unsigned long value;
	int ret;

	switch (a->attr_id) {
	case 1:
		if (!ptr)
			return 0;
		ret = kstrtoul(skip_spaces(buf), 0, &value);
		if (ret)
			return ret;
		if (value != (unsigned int)value)
			return -ERANGE;
		if (!strcmp(a->attr.name, "sync_decompress") && value > 2)
			return -EINVAL;
		*(unsigned int *)ptr = value;
		return len;
	case 2:
		if (!ptr)
			return 0;
		ret = kstrtoul(skip_spaces(buf), 0, &value);
		if (ret)
			return ret;
		if (value > 1)
			return -EINVAL;
		*(bool *)ptr = !!value;
		if (!strcmp(a->attr.name, "iostat_enable") && !sbi->iostat->iostat_enable)
			erofs_iostat_latency_stats_reset(sbi);
		return len;
	case 3:
		if (!ptr)
			return 0;
		/* Stock parser/reset mutate the sysfs input in place. */
		ret = erofs_iostat_config_parse(sbi, (char *)buf);
		return ret ? ret : (ssize_t)len;
	case 5:
		if (!ptr)
			return 0;
		ret = erofs_iostat_daily_stats_reset(sbi, (char *)buf);
		return ret ? ret : (ssize_t)len;
	}
	return 0;
}
