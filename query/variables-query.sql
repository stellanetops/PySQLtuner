SELECT
  `gvar`.`VARIABLE_NAME` AS `NAME`,
  `gvar`.`VARIABLE_VALUE` AS `VALUE`
FROM
  `performance_schema`.`global_variables` AS `gvar`
UNION
SELECT
  `svar`.`VARIABLE_NAME` AS `NAME`,
  `svar`.`VARIABLE_VALUE` AS `VALUE`
FROM
  `performance_schema`.`session_variables` AS `svar`;
