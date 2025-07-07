
use std::fmt::Debug;

/// Trait for numeric types that can be binned
pub trait OptimalNumberBinner: 
    Copy + 
    Debug + 
    PartialOrd + 
    PartialEq + 
    std::ops::Add<Output = Self> + 
    std::ops::Sub<Output = Self> + 
    std::ops::Mul<Output = Self> + 
    std::ops::Div<Output = Self>
{
    /// Convert to f64 for calculations
    fn to_f64(self) -> f64;
    
    /// Convert from f64 (for calculations)
    fn from_f64(val: f64) -> Self;
    
    /// Create a value representing 2 (for midpoint calculations)
    fn two() -> Self;
    
    /// Calculate midpoint between two values
    fn midpoint(a: Self, b: Self) -> Self {
        (a + b) / Self::two()
    }
    
    /// Check if value is valid (not NaN/infinite for floats)
    fn is_valid(self) -> bool;
    
    /// Create a hash key for value counting
    fn hash_key(self) -> String;
    
    /// Calculate distance between two values
    fn distance(a: Self, b: Self) -> f64 {
        if a >= b {
            (a - b).to_f64()
        } else {
            (b - a).to_f64()
        }
    }
    
    /// Zero value
    fn zero() -> Self;
}

impl OptimalNumberBinner for i64 {
    fn to_f64(self) -> f64 {
        self as f64
    }
    
    fn from_f64(val: f64) -> Self {
        val as i64
    }
    
    fn two() -> Self {
        2
    }
    
    fn is_valid(self) -> bool {
        true // i64 is always valid
    }
    
    fn hash_key(self) -> String {
        self.to_string()
    }
    
    fn zero() -> Self {
        0
    }
}

impl OptimalNumberBinner for f64 {
    fn to_f64(self) -> f64 {
        self
    }
    
    fn from_f64(val: f64) -> Self {
        val
    }
    
    fn two() -> Self {
        2.0
    }
    
    fn is_valid(self) -> bool {
        !self.is_nan() && !self.is_infinite()
    }
    
    fn hash_key(self) -> String {
        format!("{:.10}", self)
    }
    
    fn zero() -> Self {
        0.0
    }
}

#[derive(Debug, Clone)]
pub struct BinResult<T: OptimalNumberBinner> {
    pub bins: Vec<Vec<T>>,
    pub bin_ranges: Vec<(T, T)>,
    pub total_cost: f64,
    pub bin_costs: Vec<f64>,
    pub boundaries: Vec<T>,
    pub frequencies: Vec<usize>,
}

#[derive(Debug, Clone)]
pub struct OptimalBinner<T: OptimalNumberBinner> {
    pub max_bins: usize,
    pub min_bin_size: usize,
    pub epsilon: f64, // For floating-point comparisons (ignored for integers)
    _phantom: std::marker::PhantomData<T>,
}

impl<T: OptimalNumberBinner> Default for OptimalBinner<T> {
    fn default() -> Self {
        Self {
            max_bins: 10,
            min_bin_size: 1,
            epsilon: 1e-10,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T: OptimalNumberBinner> OptimalBinner<T> {
    pub fn new(max_bins: usize, min_bin_size: usize) -> Self {
        Self {
            max_bins,
            min_bin_size,
            epsilon: 1e-10,
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn new_with_epsilon(max_bins: usize, min_bin_size: usize, epsilon: f64) -> Self {
        Self {
            max_bins,
            min_bin_size,
            epsilon,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Main function to perform optimal binning
    pub fn fit(&self, data: &[T]) -> Result<BinResult<T>, String> {
        if data.is_empty() {
            return Err("Input data cannot be empty".to_string());
        }

        if data.len() < self.min_bin_size {
            return Err("Data size is smaller than minimum bin size".to_string());
        }

        // Check for invalid values (NaN/infinite for floats)
        if data.iter().any(|&x| !x.is_valid()) {
            return Err("Data contains invalid values (NaN or infinite)".to_string());
        }

        // Sort data
        let mut sorted_data = data.to_vec();
        sorted_data.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        
        // Check if all values are the same
        let first_val = sorted_data[0];
        let all_same = sorted_data.iter().all(|&x| x == first_val);
        
        if all_same {
            // All values are the same, create single bin
            return Ok(BinResult {
                bins: vec![sorted_data.clone()],
                bin_ranges: vec![(sorted_data[0], sorted_data[0])],
                total_cost: 0.0,
                bin_costs: vec![0.0],
                boundaries: vec![sorted_data[0], sorted_data[0]],
                frequencies: vec![sorted_data.len()],
            });
        }

        // Find optimal number of bins using dynamic programming
        let optimal_bins = self.find_optimal_bins(&sorted_data)?;
        
        Ok(optimal_bins)
    }

    /// Calculate variance for a subset of data
    fn calculate_variance(&self, data: &[T]) -> f64 {
        if data.len() <= 1 {
            return 0.0;
        }

        let mean = data.iter().map(|&x| x.to_f64()).sum::<f64>() / data.len() as f64;
        let variance = data.iter()
            .map(|&x| {
                let diff = x.to_f64() - mean;
                diff * diff
            })
            .sum::<f64>() / data.len() as f64;
        
        variance
    }

    /// Calculate cost (weighted variance) for a bin
    fn calculate_bin_cost(&self, data: &[T]) -> f64 {
        if data.is_empty() {
            return f64::INFINITY;
        }
        
        let variance = self.calculate_variance(data);
        let weight = data.len() as f64;
        
        // Cost is weighted variance
        variance * weight
    }

    /// Dynamic programming approach to find optimal binning
    fn find_optimal_bins(&self, data: &[T]) -> Result<BinResult<T>, String> {
        let n = data.len();
        let max_k = std::cmp::min(self.max_bins, n / self.min_bin_size);
        
        if max_k == 0 {
            return Err("Cannot create valid bins with given constraints".to_string());
        }

        // dp[i][k] = minimum cost to partition data[0..i] into k bins
        let mut dp = vec![vec![f64::INFINITY; max_k + 1]; n + 1];
        let mut splits = vec![vec![0; max_k + 1]; n + 1];

        // Base case: 0 elements, 0 bins
        dp[0][0] = 0.0;

        // Fill DP table
        for i in 1..=n {
            for k in 1..=std::cmp::min(i / self.min_bin_size, max_k) {
                // Try all possible positions for the last bin
                for j in ((k-1) * self.min_bin_size)..i {
                    if i - j >= self.min_bin_size {
                        let bin_data = &data[j..i];
                        let bin_cost = self.calculate_bin_cost(bin_data);
                        let total_cost = dp[j][k-1] + bin_cost;
                        
                        if total_cost < dp[i][k] {
                            dp[i][k] = total_cost;
                            splits[i][k] = j;
                        }
                    }
                }
            }
        }

        // Find the optimal number of bins
        let mut best_k = 1;
        let mut best_cost = dp[n][1];
        
        for k in 2..=max_k {
            if dp[n][k] < best_cost {
                best_cost = dp[n][k];
                best_k = k;
            }
        }

        // Reconstruct the solution
        let mut bins = Vec::new();
        let mut bin_ranges = Vec::new();
        let mut bin_costs = Vec::new();
        
        let mut current_end = n;
        let mut current_k = best_k;
        
        while current_k > 0 {
            let start = splits[current_end][current_k];
            let bin_data = data[start..current_end].to_vec();
            let bin_cost = self.calculate_bin_cost(&bin_data);
            
            bins.push(bin_data.clone());
            bin_ranges.push((bin_data[0], bin_data[bin_data.len() - 1]));
            bin_costs.push(bin_cost);
            
            current_end = start;
            current_k -= 1;
        }

        // Reverse to get correct order
        bins.reverse();
        bin_ranges.reverse();
        bin_costs.reverse();

        // Calculate boundaries and frequencies
        let boundaries = self.calculate_boundaries(&bin_ranges);
        let frequencies: Vec<usize> = bins.iter().map(|bin| bin.len()).collect();

        Ok(BinResult {
            bins,
            bin_ranges,
            total_cost: best_cost,
            bin_costs,
            boundaries,
            frequencies,
        })
    }

    /// Calculate bin boundaries (cut points between bins)
    pub fn calculate_boundaries(&self, bin_ranges: &[(T, T)]) -> Vec<T> {
        if bin_ranges.is_empty() {
            return vec![];
        }
        
        let mut boundaries = Vec::new();
        
        // Add the minimum value as the first boundary
        boundaries.push(bin_ranges[0].0);
        
        // Calculate boundaries between consecutive bins
        for i in 0..bin_ranges.len() - 1 {
            let current_max = bin_ranges[i].1;
            let next_min = bin_ranges[i + 1].0;
            
            // Use midpoint for boundary calculation
            let boundary = T::midpoint(current_max, next_min);
            boundaries.push(boundary);
        }
        
        // Add the maximum value as the last boundary
        let last_idx = bin_ranges.len() - 1;
        boundaries.push(bin_ranges[last_idx].1);
        
        boundaries
    }

    /// Predict which bin a value belongs to
    pub fn predict(&self, result: &BinResult<T>, value: T) -> Option<usize> {
        if !value.is_valid() {
            return None;
        }

        for (i, &(min_val, max_val)) in result.bin_ranges.iter().enumerate() {
            if value >= min_val && value <= max_val {
                return Some(i);
            }
        }
        
        // If not in any range, find closest bin
        let mut closest_bin = 0;
        let mut min_distance = f64::INFINITY;
        
        for (i, &(min_val, max_val)) in result.bin_ranges.iter().enumerate() {
            let distance = if value < min_val {
                T::distance(min_val, value)
            } else if value > max_val {
                T::distance(value, max_val)
            } else {
                0.0
            };
            
            if distance < min_distance {
                min_distance = distance;
                closest_bin = i;
            }
        }
        
        Some(closest_bin)
    }

    /// Get frequency (count) of elements in each bin
    pub fn bin_frequency(&self, result: &BinResult<T>) -> Vec<usize> {
        result.bins.iter().map(|bin| bin.len()).collect()
    }

    /// Get the bin edges for histogram-like usage
    pub fn get_bin_edges(&self, result: &BinResult<T>) -> Vec<T> {
        if result.bin_ranges.is_empty() {
            return vec![];
        }
        
        let mut edges = Vec::new();
        
        // First edge is the minimum of the first bin
        edges.push(result.bin_ranges[0].0);
        
        // Calculate edges between bins
        for i in 0..result.bin_ranges.len() - 1 {
            let current_max = result.bin_ranges[i].1;
            let next_min = result.bin_ranges[i + 1].0;
            let edge = T::midpoint(current_max, next_min);
            edges.push(edge);
        }
        
        // Last edge is the maximum of the last bin
        let last_idx = result.bin_ranges.len() - 1;
        edges.push(result.bin_ranges[last_idx].1);
        
        edges
    }
}

// Type aliases for convenience
pub type IntegerBinner = OptimalBinner<i64>;
pub type F64Binner = OptimalBinner<f64>;
pub type IntegerBinResult = BinResult<i64>;
pub type F64BinResult = BinResult<f64>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integer_binning() {
        let opt_bins: IntegerBinner = OptimalBinner::new(3, 2);
        let data = vec![1, 2, 3, 8, 9, 10, 15, 16, 17, 18];
        
        let result = opt_bins.fit(&data).unwrap();
        
        assert!(result.bins.len() <= 3);
        assert!(result.bins.len() >= 1);
        
        // Check that all original data is preserved
        let mut all_binned_data: Vec<i64> = Vec::new();
        for bin in &result.bins {
            all_binned_data.extend(bin);
        }
        all_binned_data.sort();
        
        let mut original_sorted = data.clone();
        original_sorted.sort();
        
        assert_eq!(all_binned_data, original_sorted);
    }

    #[test]
    fn test_f64_binning() {
        let opt_bins: F64Binner = OptimalBinner::new(3, 2);
        let data = vec![1.0, 2.0, 3.0, 8.0, 9.0, 10.0, 15.0, 16.0, 17.0, 18.0];
        
        let result = opt_bins.fit(&data).unwrap();
        
        assert!(result.bins.len() <= 3);
        assert!(result.bins.len() >= 1);
        
        // Check that all original data is preserved
        let mut all_binned_data: Vec<f64> = Vec::new();
        for bin in &result.bins {
            all_binned_data.extend(bin);
        }
        all_binned_data.sort_by(|a, b| a.partial_cmp(b).unwrap());
        
        let mut original_sorted = data.clone();
        original_sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        
        assert_eq!(all_binned_data, original_sorted);
    }

    #[test]
    fn test_integer_single_value() {
        let opt_bins: IntegerBinner = OptimalBinner::default();
        let data = vec![5, 5, 5, 5, 5];
        
        let result = opt_bins.fit(&data).unwrap();
        
        assert_eq!(result.bins.len(), 1);
        assert_eq!(result.total_cost, 0.0);
    }

    #[test]
    fn test_f64_single_value() {
        let opt_bins: F64Binner = OptimalBinner::default();
        let data = vec![5.0, 5.0, 5.0, 5.0, 5.0];
        
        let result = opt_bins.fit(&data).unwrap();
        
        assert_eq!(result.bins.len(), 1);
        assert_eq!(result.total_cost, 0.0);
    }

    #[test]
    fn test_integer_prediction() {
        let opt_bins: IntegerBinner = OptimalBinner::new(2, 2);
        let data = vec![1, 2, 3, 10, 11, 12];
        
        let result = opt_bins.fit(&data).unwrap();
        
        // Test prediction
        assert_eq!(opt_bins.predict(&result, 2), Some(0));  // Should be in first bin
        assert_eq!(opt_bins.predict(&result, 11), Some(1)); // Should be in second bin
    }

    #[test]
    fn test_f64_prediction() {
        let opt_bins: F64Binner = OptimalBinner::new(2, 2);
        let data = vec![1.0, 2.0, 3.0, 10.0, 11.0, 12.0];
        
        let result = opt_bins.fit(&data).unwrap();
        
        // Test prediction
        assert_eq!(opt_bins.predict(&result, 2.0), Some(0));  // Should be in first bin
        assert_eq!(opt_bins.predict(&result, 11.0), Some(1)); // Should be in second bin
    }

    #[test]
    fn test_f64_nan_infinite_values() {
        let opt_bins: F64Binner = OptimalBinner::default();
        
        // Test NaN
        let data_nan = vec![1.0, 2.0, f64::NAN, 4.0];
        assert!(opt_bins.fit(&data_nan).is_err());
        
        // Test infinity
        let data_inf = vec![1.0, 2.0, f64::INFINITY, 4.0];
        assert!(opt_bins.fit(&data_inf).is_err());
    }

    #[test]
    fn test_boundaries_and_frequencies() {
        let opt_bins: IntegerBinner = OptimalBinner::new(3, 2);
        let data = vec![1, 2, 3, 8, 9, 10, 15, 16, 17, 18];
        
        let result = opt_bins.fit(&data).unwrap();
        
        // Test boundaries
        assert_eq!(result.boundaries.len(), result.bins.len() + 1);
        
        // Test frequencies
        assert_eq!(result.frequencies.len(), result.bins.len());
        
        // Sum of frequencies should equal total data points
        let total_freq: usize = result.frequencies.iter().sum();
        assert_eq!(total_freq, data.len());
        
        // Each frequency should match the actual bin size
        for (i, &freq) in result.frequencies.iter().enumerate() {
            assert_eq!(freq, result.bins[i].len());
        }
    }

    #[test]
    fn test_bin_frequency_method() {
        let opt_bins: IntegerBinner = OptimalBinner::new(2, 1);
        let data = vec![1, 2, 3, 10, 11];
        
        let result = opt_bins.fit(&data).unwrap();
        let frequencies = opt_bins.bin_frequency(&result);
        
        // Sum should equal total data points
        let total: usize = frequencies.iter().sum();
        assert_eq!(total, data.len());
        
        // Each frequency should be positive
        for &freq in &frequencies {
            assert!(freq > 0);
        }
        
        // Frequencies should match the frequencies field in result
        assert_eq!(frequencies, result.frequencies);
    }

    #[test]
    fn test_empty_data() {
        let opt_bins_int: IntegerBinner = OptimalBinner::default();
        let opt_bins_f64: F64Binner = OptimalBinner::default();
        
        let empty_int: Vec<i64> = vec![];
        let empty_f64: Vec<f64> = vec![];
        
        assert!(opt_bins_int.fit(&empty_int).is_err());
        assert!(opt_bins_f64.fit(&empty_f64).is_err());
    }

    #[test]
    fn test_bin_edges() {
        let opt_bins: F64Binner = OptimalBinner::new(2, 2);
        let data = vec![1.0, 2.0, 10.0, 11.0];
        
        let result = opt_bins.fit(&data).unwrap();
        let edges = opt_bins.get_bin_edges(&result);
        
        // Should have one more edge than bins
        assert_eq!(edges.len(), result.bins.len() + 1);
        
        // Edges should be in ascending order
        for i in 1..edges.len() {
            assert!(edges[i] >= edges[i-1]);
        }
    }
}
