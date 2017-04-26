SELECT
  SUBSTRING(`hsbfit`.`event_name`, 14) AS `IO_TYPE`,
  MAX(`hsbfit`.`max_latency`) AS `MAX_LATENCY`
FROM
  `sys`.`host_summary_by_file_io_type` AS `hsbfit`
GROUP BY
  SUBSTRING(`hsbfit`.`event_name`, 14)
ORDER BY
  MAX(`hsbfit`.`max_latency`) DESC;
