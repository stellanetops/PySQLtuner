SELECT
  `hsbsl`.`host` AS `HOST`,
  `hsbsl`.`lock_latency` AS `LOCK_LATENCY`
FROM
  `sys`.`host_summary_by_statement_latency` AS `hsbsl`
ORDER BY
  `hsbsl`.`lock_latency` DESC
LIMIT 5;
