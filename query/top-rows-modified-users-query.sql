SELECT
  `usbsl`.`user` AS `USER`,
  `usbsl`.`rows_affected` AS `ROWS_AFFECTED`
FROM
  `sys`.`user_summary_by_statement_latency` AS `usbsl`
ORDER BY
  `usbsl`.`rows_affected` DESC
LIMIT 5;
