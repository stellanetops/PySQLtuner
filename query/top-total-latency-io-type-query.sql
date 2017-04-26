SELECT
  SUBSTRING(`hsbs`.`event_name`, 7) AS `IO_TYPE`,
  ROUND(SUM(`hsbs`.`total_latency`), 1) AS `TOTAL_LATENCY`
FROM
  `sys`.`host_summary_by_file_io_type` AS `hsbs`
GROUP BY
  SUBSTRING(`hsbs`.`event_name`, 7)
ORDER BY
  SUM(`hsbs`.`total_latency`) DESC;
