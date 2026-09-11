# rodin OrangeFox installer

Reviewed AnyKernel template from the installer used in run 34551018761.
Includes the verified AArch64 executables previously sourced from EVONIX v2.0:
https://github.com/NEESCHAL-3/EVONIX-kernel/releases/download/v2.0/EVONIX-v2.0-RODIN.zip
Original source archive SHA256:
`12215bb52d68d6daaf408de6dcc5623ab5e5ca7483342a70b3302598616f9a23`.
AnyKernel license retained in `rodin/LICENSE`. Local core changes validate the
repacked payload and verify the full boot partition hash after writing.

The committed template checksum list pins every bundled file. The build emits
an actual `.zip` containing `META-INF`, `anykernel.sh`, tools and `Image`, plus
its internal checksum list. GitHub's artifact download may wrap that ZIP; flash
the inner file named `Revenant-rodin-...-OrangeFox.zip`, not the evidence bundle.

Installer requires rodin, a recognized slot, 64 MiB boot, no reported active
snapshot merge, and the exact DyperOS 3.0.304 stock boot hash. It writes boot only.
Signature/ABI gates do not establish runtime behavior. Keep exact full stock
boot available outside the phone for fastboot recovery. Never wipe data.
