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

test "$(sed -n 's/^VERSION = //p' Makefile)" = 6
test "$(sed -n 's/^PATCHLEVEL = //p' Makefile)" = 6
test "$(sed -n 's/^SUBLEVEL = //p' Makefile)" = 156

# Apply the complete official Google BBRv3 series rather than copying one file.
while IFS= read -r commit; do
    case "$commit" in ''|'#'*) continue ;; esac
    git merge-base --is-ancestor "$commit" "$BBR_SOURCE_COMMIT"
    git cherry-pick "$commit"
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
