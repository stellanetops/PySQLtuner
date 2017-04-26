SELECT
  `hstsum`.`host` AS `HOST`,
  `hstsum`.`total_connections` AS `TOTAL_CONNECTIONS`
FROM
  `sys`.`host_summary` AS `hstsum`
ORDER BY
  `hstsum`.`total_connections` DESC
LIMIT 5;
