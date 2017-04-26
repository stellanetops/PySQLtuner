SELECT
  `hsbsl`.`host` AS `HOST`,
  `hsbsl`.`rows_sent` AS `ROWS_SENT`
FROM
  `sys`.`host_summary_by_statement_latency` AS `hsbsl`
ORDER BY
  `hsbsl`.`rows_sent` DESC
LIMIT 5;
