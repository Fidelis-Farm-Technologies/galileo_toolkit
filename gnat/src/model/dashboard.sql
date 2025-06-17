# ---------------------------------------------------------
# flow
# ---------------------------------------------------------
SELECT bucket as time, fsum(value)
FROM read_parquet('/metrics/*/*/*/*.parquet')
WHERE $__timeFilter(bucket) AND name='flow'
GROUP BY all
ORDER BY all;

# ---------------------------------------------------------
# bits
# ---------------------------------------------------------
SELECT bucket as time, (fsum(value) * 8) sbits
FROM read_parquet('/metrics/*/*/*/*.parquet')
WHERE $__timeFilter(bucket) AND name='bytes' AND key='sbytes'
GROUP BY all
ORDER BY all;

SELECT bucket as time, (fsum(value) * 8) sbits
FROM read_parquet('/metrics/*/*/*/*.parquet')
WHERE $__timeFilter(bucket) AND name='bytes' AND key='dbytes'
GROUP BY all
ORDER BY all;

# ---------------------------------------------------------
# pkts
# ---------------------------------------------------------
SELECT bucket as time, fsum(value)
FROM read_parquet('/metrics/*/*/*/*.parquet')
WHERE $__timeFilter(bucket) AND name='pkts' AND key='spkts'
GROUP BY all
ORDER BY all;

SELECT bucket as time, fsum(value)
FROM read_parquet('/metrics/*/*/*/*.parquet')
WHERE $__timeFilter(bucket) AND name='pkts' AND key='dpkts'
GROUP BY all
ORDER BY all;

# ---------------------------------------------------------
# proto
# ---------------------------------------------------------
SELECT bucket as time, key, fsum(value) as total
FROM read_parquet('/metrics/*/*/*/*.parquet')
WHERE $__timeFilter(bucket) AND name='proto'
GROUP BY all
ORDER BY all
LIMIT 10;

# ---------------------------------------------------------
# daddr
# ---------------------------------------------------------
SELECT bucket as time, key, fsum(value) as total
FROM read_parquet('/metrics/*/*/*/*.parquet')
WHERE $__timeFilter(bucket) AND name='daddr'
GROUP BY all
ORDER BY all
LIMIT 10;

# ---------------------------------------------------------
# appid
# ---------------------------------------------------------
SELECT bucket as time, key, fsum(value) as total
FROM read_parquet('/metrics/*/*/*/*.parquet')
WHERE $__timeFilter(bucket) AND name='appid'
GROUP BY all
ORDER BY all 
LIMIT 10;

# ---------------------------------------------------------
# dns
# ---------------------------------------------------------
SELECT key, fsum(value) as total
FROM read_parquet('/metrics/*/*/*/*.parquet')
WHERE $__timeFilter(bucket) AND name='dns'
GROUP BY all
ORDER BY all
LIMIT 100;
