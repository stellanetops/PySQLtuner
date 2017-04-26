SELECT
  `usbsl`.`user` AS `USER`,
  `usbsl`.`full_scans` AS `FULL_SCANS`
FROM
  `sys`.`user_summary_by_statement_latency` AS `usbsl`
ORDER BY
  `usbsl`.`full_scans` DESC
LIMIT 5;
