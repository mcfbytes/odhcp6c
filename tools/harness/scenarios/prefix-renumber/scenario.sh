# prefix-renumber: SLAAC prefix renumbering / lifetime-0 withdrawal.
#
# A scapy RA backend advertises a SLAAC PIO (2001:db8:1::/64) so odhcp6c forms a
# RA_ADDRESSES entry. We then inject the SAME prefix with valid-lifetime 0, which
# per RFC 4862 withdraws the address: entry_to_env still emits invalid prefix/RA
# entries (see src/script_worker.c entry_to_env), but the configured address must be
# gone from the FINAL ra-updated record.
#
# This needs harness_assert_last (lib/assert.sh): a plain not_contains would
# wrongly fail on the first record, which legitimately still carries the prefix.

scenario_backend() {
	echo "scapy ra --respond-rs --prefix 2001:db8:1:: --prefix-len 64 --prefix-valid 300 --prefix-preferred 120"
}

scenario_odhcp6c() { echo "$HARNESS_VETH_CLIENT"; }

scenario_drive() {
	wait_for_action ra-updated 30
	# The scenario_backend RA sender runs with --count 0, so it re-advertises
	# this prefix at valid=300 every --interval second. Stop it before the
	# withdrawal: otherwise the next periodic RA races in and re-adds the address
	# immediately after we remove it, making the "final record" nondeterministic.
	harness_backend_stop
	# Re-advertise the SAME prefix with valid-lifetime 0 -> withdrawal
	# (draft-ietf-6man-slaac-renum, src/ra.c: a lifetime-0 PIO removes the prefix).
	harness_inject ra --prefix 2001:db8:1:: --prefix-len 64 --prefix-valid 0 --prefix-preferred 0 --count 1
	# Wait for odhcp6c to emit a FRESH ra-updated record with the prefix gone.
	# A bare "wait_for_action ra-updated" would return immediately (one already
	# exists) and not prove the withdrawal was processed.
	wait_for "$HARNESS_TIMEOUT" "prefix withdrawn from final ra-updated record" \
		_prefix_renumber_withdrawn \
		|| fatal "odhcp6c did not withdraw the prefix after the lifetime-0 RA"
}

# True once the most recent ra-updated record no longer carries the renumbered
# prefix in RA_ADDRESSES (the SLAAC address list; see entry_to_env).
_prefix_renumber_withdrawn() {
	_pr_last=""
	for rec in "$HARNESS_CAPTURE"/rec.*; do
		[ -e "$rec" ] || continue
		[ "$(_record_action "$rec")" = ra-updated ] && _pr_last="$rec"
	done
	[ -n "$_pr_last" ] || return 1
	! _record_get "$_pr_last" RA_ADDRESSES | grep -q "2001:db8:1:"
}

scenario_assert() {
	# Learned at some point...
	harness_assert_one  ra-updated RA_ADDRESSES contains 2001:db8:1:
	# ...and absent from the FINAL record after the lifetime-0 re-advertisement.
	harness_assert_last ra-updated RA_ADDRESSES not_contains 2001:db8:1:
}
