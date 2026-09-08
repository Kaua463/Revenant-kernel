#!/bin/bash
set -euo pipefail

repo_root=${REVENANT_REPO_ROOT:?set REVENANT_REPO_ROOT}
source "$repo_root/configs/rodin-source.lock"

test "$(git rev-parse HEAD)" = "$RODIN_CLEAN_COMMIT"
test -z "$(git status --porcelain)"
git config user.name 'Revenant LTS Port'
git config user.email 'actions@users.noreply.github.com'

# ACK first: it contains Android-specific fixes through Linux 6.6.142. Prefer
# the maintained ACK side on common-code conflicts, but retain rodin's clk
# Makefile because the MT6899 modules provide the MediaTek clock drivers.
git merge --no-ff --no-commit -X theirs "$ANDROID_LTS_COMMIT" || true
test -f .git/MERGE_HEAD
git diff --name-only --diff-filter=U | sort > "$repo_root/ack-unmerged.txt"
diff -u "$repo_root/configs/ack-6.6.142-delete-conflicts.txt" "$repo_root/ack-unmerged.txt"
git add -A
git restore --source="$RODIN_CLEAN_COMMIT" --staged --worktree drivers/clk/Makefile
test -z "$(git diff --name-only --diff-filter=U)"
git commit -m "Merge Android 15 ACK LTS through 6.6.142"

# Linux stable supplies 6.6.143..6.6.156. On conflicts, retain ACK's Android
# adaptation; every conflict is captured in the merge log and build evidence.
git merge --no-ff --no-commit -X ours "$LINUX_STABLE_COMMIT" || true
test -f .git/MERGE_HEAD
git diff --name-only --diff-filter=U | sort > "$repo_root/stable-unmerged.txt"
diff -u "$repo_root/configs/stable-6.6.156-delete-conflicts.txt" "$repo_root/stable-unmerged.txt"
while IFS= read -r path; do
    git rm -- "$path"
done < "$repo_root/configs/stable-6.6.156-delete-conflicts.txt"
test -z "$(git diff --name-only --diff-filter=U)"
git commit -m "Merge Linux stable through 6.6.156"

# Recursive merge resolution can combine old Android/vendor sides with only
# part of a later stable change. Keep each proven coupled implementation set
# at the exact 6.6.156 revision instead of masking compile errors piecemeal.
while IFS= read -r source_file; do
    git restore --source="$LINUX_STABLE_COMMIT" --staged --worktree -- "$source_file"
done < "$repo_root/configs/stable-6.6.156-consistency-files.txt"
git commit -m "Restore coupled Linux 6.6.156 implementation sets"

test "$(sed -n 's/^VERSION = //p' Makefile)" = 6
test "$(sed -n 's/^PATCHLEVEL = //p' Makefile)" = 6
test "$(sed -n 's/^SUBLEVEL = //p' Makefile)" = 156

# Apply the complete official Google BBRv3 series rather than copying one file.
# Three commits conflict only because Linux 6.13 reorganized tcp_sock around
# cacheline groups. Keep the 6.6 Android layout and apply their semantic fields
# into existing padding so offsets and structure size remain stable.
while IFS= read -r commit; do
    case "$commit" in ''|'#'*) continue ;; esac
    git merge-base --is-ancestor "$commit" "$BBR_SOURCE_COMMIT"
    case "$commit" in
        a627517bdfe01967c3f8b931cfce99abfa878ef5)
            if ! git cherry-pick "$commit"; then
                test "$(git diff --name-only --diff-filter=U)" = include/net/tcp.h
                git checkout --ours include/net/tcp.h
                perl -0pi -e 's/(static inline u32 tcp_stamp_us_delta\(u64 t1, u64 t0\)\n\{\n\treturn max_t\(s64, t1 - t0, 0\);\n\}\n)/$1\nstatic inline u32 tcp_stamp32_us_delta(u32 t1, u32 t0)\n{\n\treturn max_t(s32, t1 - t0, 0);\n}\n/' include/net/tcp.h
                sed -i 's/u64 first_tx_mstamp;/u32 first_tx_mstamp;/' include/net/tcp.h
                sed -i 's/u64 delivered_mstamp;/u32 delivered_mstamp;/' include/net/tcp.h
                grep -q 'tcp_stamp32_us_delta' include/net/tcp.h
                git add include/net/tcp.h
                git cherry-pick --continue
            fi
            ;;
        4d2e56435d43a59d32890042b0ef13f6da6bac50)
            if ! git cherry-pick "$commit"; then
                test "$(git diff --name-only --diff-filter=U)" = include/linux/tcp.h
                git checkout --ours include/linux/tcp.h
                sed -i 's/unused:5;/fast_ack_mode:1, \/\* ACK without rwin delay \*\/\n\t\tunused:4;/' include/linux/tcp.h
                grep -q 'fast_ack_mode:1' include/linux/tcp.h
                git add include/linux/tcp.h
                git cherry-pick --continue
            fi
            ;;
        a631934cbcd8cddc4bac7d3fb91f890a3c07cd85)
            if ! git cherry-pick "$commit"; then
                test "$(git diff --name-only --diff-filter=U)" = include/linux/tcp.h
                git checkout --ours include/linux/tcp.h
                sed -i 's/unused:4;/tlp_orig_data_app_limited:1, \/\* app-limited before TLP rtx \*\/\n\t\tunused:3;/' include/linux/tcp.h
                grep -q 'tlp_orig_data_app_limited:1' include/linux/tcp.h
                git add include/linux/tcp.h
                git cherry-pick --continue
            fi
            ;;
        *) git cherry-pick -X theirs "$commit" ;;
    esac
done < "$repo_root/configs/bbr-v3.commits"

# KernelSU Next is kept out of the source lockstep and symlinked at its pinned
# release commit, exactly as kbuild expects.
test "$(git -C ../KernelSU-Next rev-parse HEAD)" = "$KSU_COMMIT"
ln -s ../../KernelSU-Next/kernel drivers/kernelsu
grep -q 'obj-$(CONFIG_KSU) += kernelsu/' drivers/Makefile || \
    printf '\nobj-$(CONFIG_KSU) += kernelsu/\n' >> drivers/Makefile
grep -q 'drivers/kernelsu/Kconfig' drivers/Kconfig || \
    sed -i '/endmenu/i source "drivers/kernelsu/Kconfig"' drivers/Kconfig

git status --short > "$repo_root/port-final-status.txt"
git log --oneline --decorate -80 > "$repo_root/port-log.txt"
