SELECT *
FROM read_parquet('/development/telemetry/*/*/*/*.parquet', hive_partitioning = true)
WHERE year = 2025 AND month = 4 ;

