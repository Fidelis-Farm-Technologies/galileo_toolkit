
/// Equal-frequency binning implementation for integer histograms
pub struct IntegerEqualFrequencyBinner {
    data: Vec<i64>,
    num_bins: usize,
}

impl IntegerEqualFrequencyBinner {
    /// Create a new IntegerEqualFrequencyBinner instance
    pub fn new(data: Vec<i64>, num_bins: usize) -> Self {
        if num_bins < 1 {
            panic!("Number of bins must be at least 1");
        }

        IntegerEqualFrequencyBinner { data, num_bins }
    }

    /// Calculate bin boundaries that will contain approximately equal
    /// number of data points in each bin
    pub fn calculate_boundaries(&self) -> Vec<i64> {
        // Create a copy of the data and sort it
        let mut sorted_data = self.data.clone();
        sorted_data.sort();

        // Create a vector to hold the boundaries
        let mut boundaries = Vec::with_capacity(self.num_bins + 1);

        // Handle empty data case
        if sorted_data.is_empty() {
            return Vec::new();
        }

        // Always include the minimum value as the first boundary
        boundaries.push(*sorted_data.first().unwrap());

        // If we only want one bin, just return min and max+1
        if self.num_bins == 1 {
            boundaries.push(sorted_data.last().unwrap() + 1);
            return boundaries;
        }

        let n = sorted_data.len();

        // Calculate the ideal number of elements per bin
        let items_per_bin = n as f64 / self.num_bins as f64;

        // Calculate boundaries
        for i in 1..self.num_bins {
            // Calculate the ideal index for this boundary
            let idx = (i as f64 * items_per_bin).round() as usize;
            let idx = std::cmp::min(idx, n - 1); // Ensure we don't go out of bounds

            // Get the value at this index
            let value = sorted_data[idx];

            // For integer data, we need to handle duplicates at the boundary carefully
            let mut boundary = value;

            // If there are duplicates at the boundary, we need to decide whether to
            // include all duplicates in the current bin or move them to the next bin

            // Find the range of indices with the same value
            let mut dup_start = idx;
            while dup_start > 0 && sorted_data[dup_start - 1] == value {
                dup_start -= 1;
            }

            let mut dup_end = idx;
            while dup_end < n - 1 && sorted_data[dup_end + 1] == value {
                dup_end += 1;
            }

            // If there are duplicates spanning the boundary, decide which bin they should go in
            if dup_start < idx && dup_end > idx {
                // Calculate the ideal bin boundary position
                let ideal_pos = i as f64 * items_per_bin;

                // Check if most duplicates should go in the current bin or next bin
                let mid_dup = (dup_start + dup_end) as f64 / 2.0;

                if mid_dup > ideal_pos {
                    // More duplicates should go in the next bin
                    // Set boundary to the current value
                    boundary = value;
                } else {
                    // More duplicates should go in the current bin
                    // Find the next different value after the duplicates
                    if dup_end < n - 1 {
                        boundary = sorted_data[dup_end + 1];
                    } else {
                        boundary = value + 1;
                    }
                }
            }

            boundaries.push(boundary);
        }

        // Always include one past the maximum value as the last boundary
        boundaries.push(sorted_data.last().unwrap() + 1);

        // Ensure boundaries are unique and strictly increasing
        let mut unique_boundaries = Vec::new();
        let mut prev_boundary = None;

        for &boundary in &boundaries {
            if prev_boundary.is_none() || Some(boundary) > prev_boundary {
                unique_boundaries.push(boundary);
                prev_boundary = Some(boundary);
            }
        }

        // If we ended up with fewer bins due to merging, we need to adjust
        if unique_boundaries.len() < 2 {
            // Ensure at least one valid bin
            if let Some(&max) = sorted_data.last() {
                if unique_boundaries.is_empty() {
                    unique_boundaries.push(*sorted_data.first().unwrap_or(&0));
                }
                unique_boundaries.push(max + 1);
            }
        }

        unique_boundaries
    }

    /// Get the bin counts - the number of elements in each bin
    pub fn bin_frequency(&self) -> Vec<usize> {
        let boundaries = self.calculate_boundaries();
        let num_bins = boundaries.len() - 1;
        let mut counts = vec![0; num_bins];

        // Count elements in each bin
        for &value in &self.data {
            // Find the bin for this value using binary search
            match boundaries.binary_search(&value) {
                Ok(idx) => {
                    // Value is exactly at a boundary
                    if idx < num_bins {
                        counts[idx] += 1;
                    }
                }
                Err(idx) => {
                    // Value is between boundaries
                    if idx > 0 && idx <= num_bins {
                        counts[idx - 1] += 1;
                    }
                }
            }
        }

        counts
    }

    /// Get a report of the bins and their contents
    pub fn bin_report(&self) -> Vec<(i64, i64, usize)> {
        let boundaries = self.calculate_boundaries();
        let counts = self.bin_frequency();

        let mut report = Vec::new();
        for i in 0..counts.len() {
            report.push((boundaries[i], boundaries[i + 1], counts[i]));
        }

        report
    }
}
