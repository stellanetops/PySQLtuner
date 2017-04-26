SELECT
  `hsbsl`.`host` AS `HOST`,
  `hsbsl`.`full_scans` AS `FULL_SCANS`
FROM
  `sys`.`host_summary_by_statement_latency` AS `hsbsl`
ORDER BY
  `hsbsl`.`full_scans` DESC
LIMIT 5;
