CREATE TABLE flow AS SELECT * FROM '/development/hbos/gnat*.parquet';
FROM histogram(flow, score);
FROM histogram(flow, outlier);

