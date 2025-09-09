package sliceutil

// Filter creates a new slice by filtering elements in s via f.
func Filter[S ~[]E, E any](s S, f func(E) bool) []E {
	result := make([]E, 0, len(s))

	for _, e := range s {
		if f(e) {
			result = append(result, e)
		}
	}

	return result
}

// Map creates a new slice by applying f to each element in s.
func Map[S ~[]E, E any, R any](s S, f func(E) R) []R {
	result := make([]R, 0, len(s))

	for _, e := range s {
		result = append(result, f(e))
	}

	return result
}
