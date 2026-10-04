# Licensing and third-party attribution

## This checker

The checker source and accompanying original documentation are distributed under
GNU General Public License version 3 only (SPDX: `GPL-3.0-only`). The complete
license is in [LICENSE](LICENSE). Third-party materials retain their applicable
copyright notices and license terms below.

This is an independent checker and filtered subscription generator. It is not an
official release of, or endorsed by, the projects named below. The source
subscriptions are inputs; no upstream checker implementation has been copied
into this checker.

## igareck/vpn-configs-for-russia

- Upstream: <https://github.com/igareck/vpn-configs-for-russia>
- License: GNU GPL version 3; upstream license file:
  <https://github.com/igareck/vpn-configs-for-russia/blob/main/LICENSE>
- Subscription inputs: `BLACK_SS+All_RUS.txt` and
  `BLACK_VLESS_RUS_mobile.txt` and `BLACK_VLESS_RUS.txt` in that repository.
- A verbatim copy of its GPLv3 license text is included as [LICENSE](LICENSE).

The upstream license file reviewed on 2026-10-02 contains the standard GPLv3
license text, including the license document's notice:

> Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>

That is the copyright notice for the license document; it is not an assertion
that the Free Software Foundation authored the subscriptions. No project-specific
copyright holder or year is invented here.

## Diversan313/apex-parser

- Upstream: <https://github.com/Diversan313/apex-parser>
- License: MIT; upstream license file:
  <https://github.com/Diversan313/apex-parser/blob/main/LICENSE>
- Subscription input: `subs/main/alive_bl.txt` in that repository.
- Exact upstream copyright notice:

> Copyright (c) 2026 Unemployed

The complete upstream MIT license, including its permission notice and warranty
disclaimer, is preserved verbatim in [licenses/apex-MIT.txt](licenses/apex-MIT.txt).
The public repository's MIT notice does not grant access to or rights in its
separate private repositories.

## VovaplusEXP/p-configs

- Upstream: <https://github.com/VovaplusEXP/p-configs>
- Input: `Splitted-By-Protocol-Secure/vless.txt` on `main`
- License: GNU GPL version 3; exact upstream file reviewed 2026-10-04:
  <https://github.com/VovaplusEXP/p-configs/blob/main/LICENSE>
- Verbatim license preserved in [licenses/vovaplus-GPL-3.0.txt](licenses/vovaplus-GPL-3.0.txt)

## mahdibland/V2RayAggregator

- Upstream: <https://github.com/mahdibland/V2RayAggregator>
- Input: `Eternity.txt` on `master`
- License: GNU GPL version 3; exact upstream file reviewed 2026-10-04:
  <https://github.com/mahdibland/V2RayAggregator/blob/master/LICENSE>
- Verbatim license preserved in [licenses/eternity-GPL-3.0.txt](licenses/eternity-GPL-3.0.txt)

Both upstream license files have Git blob SHA
`f288702d2fa16d3cdf0035b15a9fcbc552cd88e7` and contain the standard GPLv3
text. No project-specific author/year notice is invented. The license-document
copyright notice remains intact. No checker code is copied from either source.
Publicly aggregated endpoints are untrusted candidate data, not endorsements or
a grant of rights to third-party network infrastructure.

## Generated subscriptions and changes

The output is a modified selection and combination of the identified public
subscription inputs, not an unmodified upstream release. This checker decodes,
parses, rejects unsupported or unsafe entries, deduplicates, tests candidates,
and selects successful configurations. Outputs may be serialized or encoded for
subscription clients. These transformation rules were prepared on 2026-10-02 and extended with conservative compatibility, bounded retry diagnostics and full snapshot sharding on 2026-10-04;
each run records its actual generation time in the accompanying report.

Distribute generated subscriptions together with this notice, the GPLv3 license
and all included upstream license notices. Preserve the GPLv3 terms for covered igareck material
and the MIT notice for covered apex material. This project's GPL designation
does not remove MIT rights in the upstream MIT portions. Public availability and
these repository licenses do not establish that every third-party endpoint is
authorized, trustworthy or lawful to use in every jurisdiction. No rights to
third-party infrastructure or trademarks are granted by this notice.

## External runtime: sing-box

The checker invokes a separately obtained sing-box executable. No sing-box binary
or source code is redistributed in this package.

- Upstream: <https://github.com/SagerNet/sing-box>
- Releases: <https://github.com/SagerNet/sing-box/releases>
- Upstream licensing notice: <https://github.com/SagerNet/sing-box#license>
- Upstream copyright notice: `Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>`

The upstream README states GPL version 3 or later and additionally states that
no derivative work may use the name or imply association with the application
without prior consent. Refer to the exact downloaded release and its dependencies
for their applicable notices. Redistributing the executable later requires a
separate review of those notices and corresponding-source obligations; the
external-download arrangement here is not a binary-redistribution license grant.

## Verification record

License texts were retrieved read-only from the public upstream repositories on
2026-10-02. This package includes no installed or executed proxy core, and no live
endpoint test is implied by the license verification.
