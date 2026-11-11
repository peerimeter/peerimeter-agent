package installstate

// Linux's POSIX ACL mask is reflected in group mode bits checked by checkTrust.
func checkExtendedTrust(string, bool, bool) error { return nil }
