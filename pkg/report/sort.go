package report

import (
	"sort"

	"github.com/aquasecurity/trivy-operator/pkg/report/templates"
)

type LessFunc func(p1, p2 *templates.CheckWithCount) bool

// multiSorter implements the Sort interface, sorting the reports within.
type multiSorter struct {
	checks []templates.CheckWithCount
	less   []LessFunc
}

// SortDesc sorts the argument slice according to the LessFunc functions passed to OrderedBy.
func (ms *multiSorter) SortDesc(reports []templates.CheckWithCount) {
	ms.checks = reports
	sort.Stable(sort.Reverse(ms))
}

// OrderedBy returns a Sorter that sorts using the LessFunc functions, in order.
// Call its Sort method to sort the data.
func OrderedBy(less ...LessFunc) *multiSorter {
	return &multiSorter{
		less: less,
	}
}

// Len is part of sort.Interface.
func (ms *multiSorter) Len() int {
	return len(ms.checks)
}

// Swap is part of sort.Interface.
func (ms *multiSorter) Swap(i, j int) {
	ms.checks[i], ms.checks[j] = ms.checks[j], ms.checks[i]
}

// Less is part of sort.Interface. It is implemented by looping along the
// less functions until it finds a comparison that discriminates between
// the two items (one is less than the other). Note that it can call the
// less functions twice per call. We could change the functions to return
// -1, 0, 1 and reduce the number of calls for greater efficiency: an
// exercise for the reader.
func (ms *multiSorter) Less(i, j int) bool {
	p, q := &ms.checks[i], &ms.checks[j]
	// Try all but the last comparison.
	var k int
	for k = 0; k < len(ms.less)-1; k++ {
		less := ms.less[k]
		switch {
		case less(p, q):
			// p < q, so we have a decision.
			return true
		case less(q, p):
			// p > q, so we have a decision.
			return false
		}
		// p == q; try the next comparison.
	}
	// All comparisons to here said "equal", so just return whatever
	// the final comparison reports.
	return ms.less[k](p, q)
}

var (
	checkCompareFunc = []LessFunc{
		func(r1, r2 *templates.CheckWithCount) bool {
			return r1.AffectedWorkloads < r2.AffectedWorkloads
		}, func(r1, r2 *templates.CheckWithCount) bool {
			return r1.Severity > r2.Severity
		}, func(r1, r2 *templates.CheckWithCount) bool {
			return r1.ID > r2.ID
		}}
)
