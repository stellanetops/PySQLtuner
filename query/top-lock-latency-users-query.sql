SELECT
  `usbsl`.`user` AS `USER`,
  `usbsl`.`lock_latency` AS `LOCK_LATENCY`
FROM
  `sys`.`user_summary_by_statement_latency` AS `usbsl`
ORDER BY
  `usbsl`.`lock_latency` DESC
LIMIT 5;
