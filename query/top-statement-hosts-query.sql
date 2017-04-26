SELECT
  `hstsum`.`host` AS `HOST`,
  `hstsum`.`statements` AS `STATEMENTS`
FROM
  `sys`.`host_summary` AS `hstsum`
ORDER BY
  `hstsum`.`statements` DESC
LIMIT 5;
