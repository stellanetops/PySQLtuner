SELECT
  `usbsl`.`user` AS `USER`,
  `usbsl`.`rows_sent` AS `ROWS_SENT`
FROM
  `sys`.`user_summary_by_statement_latency` AS `usbsl`
ORDER BY
  `usbsl`.`rows_sent` DESC
LIMIT 5;
