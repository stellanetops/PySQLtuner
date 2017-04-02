SELECT
  `eng`.`ENGINE`,
  `eng`.`SUPPORT`
FROM
  `information_schema`.`ENGINES` AS `eng`
WHERE
  `eng`.`ENGINE` NOT IN (
      'performance_schema',
      'MyISAM',
      'MERGE',
      'MEMORY'
  )
ORDER BY
  `eng`.`ENGINE` ASC;