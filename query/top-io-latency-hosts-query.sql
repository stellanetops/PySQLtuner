SELECT
  `hstsum`.`host` AS `HOST`,
  `hstsum`.`file_io_latency` AS `FILE_IO_LATENCY`
FROM
  `sys`.`host_summary` AS `hstsum`
ORDER BY
  `hstsum`.`rows_affected` DESC
LIMIT 5;
