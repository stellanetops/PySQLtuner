SELECT
  CONCAT('`', `tbl`.`TABLE_SCHEMA`, '`.`', `tbl`.`TABLE_NAME`, '`') AS `TABLE`,
  `tbl`.`DATA_FREE` AS `DATA_FREE`
FROM
  `information_schema`.`TABLES` AS `tbl`
WHERE
  `tbl`.`TABLE_SCHEMA` NOT IN (
    'information_schema',
    'mysql',
    'performance_schema'
  )
  AND
    `tbl`.`DATA_LENGTH` / POWER(1024, 2) > 100
  AND
    `DATA_FREE` * 100 / (`tbl`.`DATA_LENGTH` + `tbl`.`INDEX_LENGTH` + `DATA_FREE`) > 10
  AND
    `tbl`.`ENGINE` <> 'MEMORY'
  :innodb_clause;
