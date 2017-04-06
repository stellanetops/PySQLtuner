SELECT
  CONCAT('`', `col`.`TABLE_SCHEMA`, '`.`', `col`.`TABLE_NAME`) AS `TABLE`
FROM
  `information_schema`.`COLUMNS` AS `col`
    INNER JOIN `information_schema`.`TABLES` AS `tbl`
      ON `col`.`TABLE_SCHEMA` = `tbl`.`TABLE_SCHEMA`
        AND `col`.`TABLE_NAME` =  `tbl`.`TABLE_NAME`
WHERE
  `col`.`TABLE_SCHEMA` NOT IN (
    'information_schema',
    'mysql',
    'performance_schema'
  )
  AND
    `tbl`.`TABLE_TYPE` <> 'VIEW'
GROUP BY
  `col`.`TABLE_SCHEMA`,
  `col`.`TABLE_NAME`
HAVING
  SUM(IF(`col`.`COLUMN_KEY` IN (
    'PRI',
    'UNI'
  ), 1, 0)) = 0;
