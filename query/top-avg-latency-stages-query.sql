SELECT
  SUBSTRING(`hsbs`.`event_name`, 7) AS `IO_TYPE`,
  MAX(`hsbs`.`avg_latency`) AS `AVG_LATENCY`
FROM
  `sys`.`host_summary_by_stages` AS `hsbs`
GROUP BY
  SUBSTRING(`hsbs`.`event_name`, 7)
ORDER BY
  MAX(`hsbs`.`avg_latency`) DESC;
