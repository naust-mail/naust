package checks

// All returns every registered check. Registration is a plain list:
// each area file contributes its checks here, nothing self-registers.
func All() []Check {
	var all []Check
	all = append(all, systemChecks()...)
	all = append(all, serviceChecks()...)
	all = append(all, httpChecks()...)
	all = append(all, dnsChecks()...)
	all = append(all, tlsChecks()...)
	all = append(all, backupChecks()...)
	return all
}
