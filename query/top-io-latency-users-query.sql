SELECT
  `usrsum`.`user` AS `USER`,
  `usrsum`.`file_io_latency` AS `FILE_IO_LATENCY`
FROM
  `sys`.`user_summary` AS `usrsum`
ORDER BY
  `usrsum`.`rows_affected` DESC
LIMIT 5;
