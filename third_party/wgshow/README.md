# wgshow attribution

[Agent documentation](../../README.md) · [MIT license](LICENSE)

The device and peer presentation is adapted and refactored from the [wgshow
example](https://github.com/zer0go/wgctrl-go/blob/47ad6fc7d7a95296fe893b49c1d4584b4eb6ac40/cmd/wgshow/main.go),
originally part of Matt Layher's wgctrl-go project and distributed under the MIT
license.

| Reference | Value |
| --- | --- |
| Source file | `cmd/wgshow/main.go` |
| Pinned revision | `47ad6fc7d7a95296fe893b49c1d4584b4eb6ac40` |
| Agent formatter | [internal/presentation/peers.go](../../internal/presentation/peers.go) |

## Adaptation

The formatter accepts only public agent snapshot data and remains independent of
OS access and Cobra. It handles missing endpoints, clock skew, disabled
keepalive and unsigned 64-bit counters. Private and preshared keys are excluded
from its input types.

The [license](LICENSE) is included with agent release package notices.
