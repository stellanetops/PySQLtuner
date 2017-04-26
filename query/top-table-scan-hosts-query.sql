SELECT
  `hstsum`.`host` AS `HOST`,
  `hstsum`.`table_scans` AS `TABLE_SCANS`
FROM
  `sys`.`host_summary` AS `hstsum`
ORDER BY
  `hstsum`.`table_scans` DESC
LIMIT 5;
