SELECT
  `hstsum`.`host` AS `HOST`,
  `hstsum`.`statement_avg_latency` AS `STATEMENT_AVG_LATENCY`
FROM
  `sys`.`host_summary` AS `hstsum`
ORDER BY
  `hstsum`.`statement_avg_latency` DESC
LIMIT 5;
