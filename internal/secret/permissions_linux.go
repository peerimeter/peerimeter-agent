package secret

// POSIX ACL group-class permissions are reflected in the mode's group mask.
// openProtected already rejects all group/other mode bits on Linux.
func checkExtendedPermissions(fd int) error { return nil }
