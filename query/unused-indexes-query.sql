SELECT
  CONCAT('`', `wait`.`object_schema`, '`.`', `wait`.`object_name`, '`') AS `SCHEMA_TABLE`,
  `wait`.`index_name` AS `INDEX`
FROM
  `performance_schema`.`table_io_waits_summary_by_index_usage` AS `wait`
WHERE
  `wait`.`index_name` IS NOT NULL
  AND
    `wait`.`count_star` = 0
  AND
    `wait`.`index_name` <> 'PRIMARY'
  AND
    `wait`.`object_schema` <> 'mysql'
ORDER BY
  `wait`.`count_star`,
  `wait`.`object_schema`,
  `wait`.`object_name`;
