/* Recovered semantic body, DyperOS 3.0.304 stock Image only.
 * Verified against ARM64 instructions and BTF; not integrated or KMI-tested.
 * Requires the matching erofs_sb_info/erofs_iostat/bio definitions.
 * Do not add null guards here and call that stock-equivalent: stock dereferences
 * sbi->iostat before checking the enable flag.
 */
void erofs_iostat_record_start(struct erofs_sb_info *sbi, struct bio *bio)
{
	if (sbi->iostat->iostat_enable)
		bio->android_oem_data1 = ktime_get();
}
