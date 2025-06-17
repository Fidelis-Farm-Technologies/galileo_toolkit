#/bin/bash
#
#
DATABASE='test.duckdb'
OBSERVE_LIST=`duckdb ${DATABASE} --list -noheader -s "SELECT DISTINCT observe FROM histogram_summary;"`
PROTO_LIST=`duckdb ${DATABASE} --list -noheader -s "SELECT DISTINCT proto FROM histogram_summary;"`
TYPE_LIST=`duckdb ${DATABASE} --list -noheader -s "SELECT DISTINCT histogram FROM histogram_summary;"`

for observe in $OBSERVE_LIST
do
    for proto in $PROTO_LIST
    do
       for type in $TYPE_LIST
       do
          FEATURE_LIST=`duckdb ${DATABASE} --list -noheader -s "SELECT DISTINCT name FROM histogram_summary WHERE observe='${observe}' AND proto='${proto}' AND histogram='${type}';"`
          for name in $FEATURE_LIST
          do
            case $type in
              string_category)
                 COUNT=`duckdb ${DATABASE} --list -noheader -s "SELECT count FROM histogram_summary WHERE observe='${observe}' AND proto='${proto}' AND name='${name}' AND histogram='${type}' LIMIT 1;"`
                 HISTOGRAM_QUERY=`duckdb ${DATABASE} --csv -header -s "SELECT key,value FROM histogram_string_category WHERE observe='${observe}' AND proto='${proto}' AND name='${name}' ORDER BY key;" | uplot bar -d, -H -t "$observe/$proto/$type/$name"`
                 echo "$observe/$proto/$type/$feature: count=${COUNT}"
                 ;;
              numeric_category)
                 COUNT=`duckdb ${DATABASE} --list -noheader -s "SELECT count FROM histogram_summary WHERE observe='${observe}' AND proto='${proto}' AND name='${name}' AND histogram='${type}' LIMIT 1;"`
                 HISTOGRAM_QUERY=`duckdb ${DATABASE} --csv -header -s "SELECT key,value FROM histogram_numeric_category WHERE observe='${observe}' AND proto='${proto}' AND name='${name}' ORDER BY key;" | uplot bar -d, -H -t "$observe/$proto/$type/$name"`
                 echo "$observe/$proto/$type/$name: count=${COUNT}"
                 ;;
              numerical)
                 BIN_WIDTH=`duckdb ${DATABASE} --list -noheader -s "SELECT bin_width FROM histogram_summary WHERE observe='${observe}' AND proto='${proto}' AND name='${name}' AND histogram='${type}' LIMIT 1;"`
                 echo "$observe/$proto/$type/$name: width=${BIN_WIDTH}"
                 HISTOGRAM_QUERY=`duckdb ${DATABASE} --csv -header -s "SELECT floor(value / ${BIN_WIDTH}) * ${BIN_WIDTH}, count(*) AS count FROM histogram_numeric WHERE observe='${observe}' AND proto='${proto}' AND name='${name}' ORDER BY key;"  | uplot bar -d, -H -t "$observe/$proto/$type/$name"`
                 ;;
              *)
                 echo "Unknow type: $type"
                 ;;
             esac
          done
       done
    done
done

