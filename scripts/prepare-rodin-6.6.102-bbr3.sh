#!/bin/bash
set -euo pipefail

repo_root=${REVENANT_REPO_ROOT:?set REVENANT_REPO_ROOT}
source "$repo_root/configs/rodin-source.lock"

test "$(git rev-parse HEAD)" = "$RODIN_CLEAN_COMMIT"
test -z "$(git status --porcelain)"
git config user.name 'Revenant Network Build'
git config user.email 'actions@users.noreply.github.com'

test "$(sed -n 's/^VERSION = //p' Makefile)" = 6
test "$(sed -n 's/^PATCHLEVEL = //p' Makefile)" = 6
test "$(sed -n 's/^SUBLEVEL = //p' Makefile)" = 102

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
