SELECT
  `sch`.`SCHEMA_NAME` AS `DATABASE`
FROM
  `information_schema`.`SCHEMATA` AS `sch`
GROUP BY
  `DATABASE`;
