SELECT
  SUM(`tbl`.`TABLE_ROWS`) AS `ROW_AMOUNT`,
  SUM(`tbl`.`DATA_LENGTH`) AS `DATA_SIZE`,
  SUM(`tbl`.`INDEX_LENGTH`) AS `INDEX_SIZE`,
  SUM(`tbl`.`DATA_LENGTH` + `tbl`.`INDEX_LENGTH`) AS `TOTAL_SIZE`,
  COUNT(`tbl`.`TABLE_NAME`) AS `TABLE_COUNT`,
  COUNT(DISTINCT(`tbl`.`TABLE_COLLATION`)) AS `COLLATION_COUNT`,
  COUNT(DISTINCT(`tbl`.`ENGINE`)) AS `ENGINE_COUNT`
FROM
  `information_schema`.`TABLES` AS `tbl`
WHERE
  `tbl`.`TABLE_SCHEMA` NOT IN (
    'information_schema',
    'mysql',
    'performance_schema'
  );
