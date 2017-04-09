SELECT
  `gstat`.`VARIABLE_NAME` AS `NAME`,
  `gstat`.`VARIABLE_VALUE` AS `VALUE`
FROM
  `performance_schema`.`global_status` AS `gstat`
UNION
SELECT
  `sstat`.`VARIABLE_NAME` AS `NAME`,
  `sstat`.`VARIABLE_VALUE` AS `VALUE`
FROM
  `performance_schema`.`session_status` AS `sstat`;
