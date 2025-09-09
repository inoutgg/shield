package sliceutil_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.inout.gg/shield/internal/sliceutil"
)

func TestFilter(t *testing.T) {
	t.Parallel()

	t.Run("Filter should work", func(t *testing.T) {
		t.Parallel()

		result := sliceutil.Filter(
			[]string{"even", "odd", "even"},
			func(v string) bool {
				return v == "odd"
			},
		)

		assert.Equal(t, []string{"odd"}, result)
	})

	t.Run("Filter should keep the slice", func(t *testing.T) {
		t.Parallel()

		result := sliceutil.Filter([]int{1, 2, 3, 4}, func(int) bool {
			return true
		})

		assert.Equal(t, []int{1, 2, 3, 4}, result)
	})

	t.Run("Filter should return empty slice", func(t *testing.T) {
		t.Parallel()

		result := sliceutil.Filter([]int{1, 2, 3, 4}, func(int) bool {
			return false
		})

		assert.Equal(t, []int{}, result)
	})

	t.Run("Filter should handle empty slice", func(t *testing.T) {
		t.Parallel()

		result := sliceutil.Filter([]int{}, func(int) bool {
			return true
		})

		assert.Equal(t, []int{}, result)
	})
}

func TestMap(t *testing.T) {
	t.Parallel()

	t.Run("Map should work", func(t *testing.T) {
		t.Parallel()

		result := sliceutil.Map(
			[]string{"even", "odd", "even"},
			func(v string) string {
				return v + "!"
			},
		)

		assert.Equal(t, []string{"even!", "odd!", "even!"}, result)
	})

	t.Run("Map should keep the slice", func(t *testing.T) {
		t.Parallel()

		result := sliceutil.Map([]int{1, 2, 3, 4}, func(v int) int {
			return v
		})

		assert.Equal(t, []int{1, 2, 3, 4}, result)
	})

	t.Run("Map should handle empty slice", func(t *testing.T) {
		t.Parallel()

		result := sliceutil.Map([]int{}, func(int) int {
			return 0
		})

		assert.Equal(t, []int{}, result)
	})
}
