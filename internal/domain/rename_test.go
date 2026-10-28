package domain

import "testing"

// A resolved rename is recorded, never announced: the program did not gain
// attack surface, and the researcher has nothing to act on. The record exists
// so the history reads continuously across the move.
func TestRenameChangeIsRecordOnly(t *testing.T) {
	k := ChangeProgramRenamed
	if !k.Classified() {
		t.Fatal("PROGRAM_RENAMED is not on either side of the alertable/record-only divide")
	}
	if k.alertOn() {
		t.Error("PROGRAM_RENAMED alerts; a rename is not an opening")
	}
	if !k.recordOnly() {
		t.Error("PROGRAM_RENAMED must be record-only")
	}
}
