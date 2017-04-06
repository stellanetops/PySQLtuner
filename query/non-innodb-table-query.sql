SELECT
  CONCAT('`', `tbl`.`TABLE_SCHEMA`, '`.`', `tbl`.`TABLE_NAME`) AS `TABLE`
FROM
  `information_schema`.`TABLES` AS `tbl`
WHERE
  `tbl`.`ENGINE` <> 'InnoDB'
  AND
    `tbl`.`TABLE_SCHEMA` NOT IN (
      'information_schema',
      'mysql',
      'performance_schema'
    );
