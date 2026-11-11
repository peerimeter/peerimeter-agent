The wgshow-style device/peer presentation is adapted and refactored from
https://github.com/zer0go/wgctrl-go/blob/47ad6fc7d7a95296fe893b49c1d4584b4eb6ac40/cmd/wgshow/main.go
(MIT, originally wgctrl-go by Matt Layher). The formatter accepts only public
agent snapshot data, remains independent of OS access/Cobra, and handles missing
endpoints, clock skew, disabled keepalive and uint64 counters. See LICENSE.
