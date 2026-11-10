//go:build race

package capture

// slow scales the time budgets of tests that guard against slow algorithms:
// the race detector makes the code several times slower.
const slow = 10
