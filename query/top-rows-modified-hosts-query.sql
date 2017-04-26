SELECT
  `hsbsl`.`host` AS `HOST`,
  `hsbsl`.`rows_affected` AS `ROWS_AFFECTED`
FROM
  `sys`.`host_summary_by_statement_latency` AS `hsbsl`
ORDER BY
  `hsbsl`.`rows_affected` DESC
LIMIT 5;
