SELECT
  `tbl`.`ENGINE` AS `ENGINE`,
  SUM(`tbl`.`DATA_LENGTH` + `tbl`.`INDEX_LENGTH`) AS `SIZE`,
  COUNT(`tbl`.`ENGINE`) AS `COUNT`,
  SUM(`tbl`.`DATA_LENGTH`) AS `DATA_SIZE`,
  SUM(`tbl`.`INDEX_LENGTH`) AS `INDEX_SIZE`
FROM
  `information_schema`.`TABLES` AS `tbl`
WHERE
  `tbl`.`TABLE_SCHEMA` NOT IN (
    'information_schema',
    'mysql',
    'performance_schema'
  )
  AND
    `tbl`.`ENGINE` IS NOT NULL
GROUP BY
  `tbl`.`ENGINE`
ORDER BY
  `eng`.`ENGINE` ASC;
