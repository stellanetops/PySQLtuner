SELECT
  SUBSTRING(`hsbfit`.`event_name`, 14) AS `IO_TYPE`,
  SUM(`hsbfit`.`total`) AS `TOTAL`
FROM
  `sys`.`host_summary_by_stages` AS `hsbfit`
GROUP BY
  SUBSTRING(`hsbfit`.`event_name`, 14)
ORDER BY
  SUM(`hsbfit`.`total`) DESC;
