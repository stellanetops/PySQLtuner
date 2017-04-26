SELECT
  `hstsum`.`host` AS `HOST`,
  `hstsum`.`file_ios` AS `FILE_IOS`
FROM
  `sys`.`host_summary` AS `hstsum`
ORDER BY
  `hstsum`.`rows_affected` DESC
LIMIT 5;
